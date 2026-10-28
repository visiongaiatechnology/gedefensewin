// STATUS: PLATIN
package operatorclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAcquireReturnsVerifiedOperatorSession(t *testing.T) {
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/session/operator" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get(BrokerHeader) != brokerValue {
			t.Errorf("broker marker missing")
		}
		if r.Header.Get("X-VGT-Request-ID") == "" {
			t.Errorf("replay id missing")
		}
		if r.Header.Get("Origin") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("operator client must not send browser/auth material")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"vgs.operator-test","client":"tray","scopes":["read"],"expiresUtc":"` +
			expires + `","subject":{"account":"TEST\\operator","administrator":false,"operator":true}}`))
	}))
	defer server.Close()
	session, err := Acquire(context.Background(), server.URL, TrayClient)
	if err != nil {
		t.Fatalf("acquire failed: %v", err)
	}
	if session.Token != "vgs.operator-test" || session.Client != TrayClient || session.Account != `TEST\operator` || !session.Operator {
		t.Fatalf("unexpected session: %+v", session)
	}
	if session.Expired(time.Now().Add(-time.Hour)) {
		t.Fatal("fresh session reported as expired")
	}
	if !session.Expired(time.Now().Add(2 * time.Hour)) {
		t.Fatal("past-expiry session not reported as expired")
	}
}

func TestAcquireRejectsMalformedAndRejectedResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"forbidden", http.StatusForbidden, `{}`},
		{"missing token", http.StatusCreated, `{"client":"tray","scopes":["read"],"expiresUtc":"2030-01-01T00:00:00Z"}`},
		{"wrong client", http.StatusCreated, `{"token":"vgs.x","client":"center-launcher","scopes":["read"],"expiresUtc":"2030-01-01T00:00:00Z"}`},
		{"trailing data", http.StatusCreated, `{"token":"vgs.x","client":"tray","scopes":["read"],"expiresUtc":"2030-01-01T00:00:00Z"}{}`},
		{"unknown field", http.StatusCreated, `{"token":"vgs.x","client":"tray","scopes":["read"],"expiresUtc":"2030-01-01T00:00:00Z","evil":1}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			if _, err := Acquire(context.Background(), server.URL, TrayClient); err == nil {
				t.Fatalf("accepted invalid broker response: %s", test.name)
			}
		})
	}
}

func TestAcquireRejectsUnsupportedClient(t *testing.T) {
	if _, err := Acquire(context.Background(), "http://127.0.0.1:1", "random"); err == nil {
		t.Fatal("unsupported client accepted")
	}
}

func TestRandomRequestIDShape(t *testing.T) {
	value, err := randomRequestID()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(value, "-")
	if len(parts) != 5 {
		t.Fatalf("request id shape invalid: %q", value)
	}
}

func traySessionResponse(expires time.Time) string {
	return `{"token":"vgs.retry-test","client":"tray","scopes":["read"],"expiresUtc":"` +
		expires.UTC().Format(time.RFC3339Nano) + `"}`
}

func TestAcquireRetriesTransientBrokerStatusWithinBoundedAttempts(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := requests.Add(1)
		if count < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(traySessionResponse(time.Now().Add(time.Hour))))
	}))
	defer server.Close()
	started := time.Now()
	session, err := Acquire(context.Background(), server.URL, TrayClient)
	if err != nil {
		t.Fatalf("transient 503/503/201 sequence was not recovered: %v", err)
	}
	if requests.Load() != maxAttempts {
		t.Fatalf("expected exactly %d requests, got %d", maxAttempts, requests.Load())
	}
	if session.Token != "vgs.retry-test" || session.Client != TrayClient {
		t.Fatalf("retried handshake returned an unexpected session: %+v", session)
	}
	if elapsed := time.Since(started); elapsed < 800*time.Millisecond {
		t.Fatalf("expected bounded 300 ms/600 ms backoff before the successful attempt, waited %v", elapsed)
	}
}

func TestAcquireDoesNotRetryDefinitiveRejections(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusConflict,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(status)
			}))
			defer server.Close()
			_, err := Acquire(context.Background(), server.URL, TrayClient)
			if err == nil {
				t.Fatalf("HTTP %d was accepted", status)
			}
			if requests.Load() != 1 {
				t.Fatalf("HTTP %d was retried %d times; it is a definitive rejection", status, requests.Load())
			}
			if !strings.Contains(err.Error(), http.StatusText(status)) && !strings.Contains(err.Error(), "HTTP") {
				t.Fatalf("HTTP %d error is not concrete: %v", status, err)
			}
		})
	}
}

func TestAcquireContextCancellationAbandonsBackoff(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := Acquire(ctx, server.URL, TrayClient)
	if err == nil {
		t.Fatal("cancelled handshake reported success")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation was not propagated: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancelled handshake kept retrying for %v", elapsed)
	}
	if requests.Load() != 1 {
		t.Fatalf("expected one attempt before cancellation, got %d", requests.Load())
	}
}

func TestAcquireClassifiesOnlyTransientStatusesForRetry(t *testing.T) {
	for _, status := range []int{
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		if !retryableStatus(status) {
			t.Fatalf("HTTP %d must be retried as transient", status)
		}
	}
	for _, status := range []int{
		http.StatusCreated,
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusConflict,
		http.StatusInternalServerError,
	} {
		if retryableStatus(status) {
			t.Fatalf("HTTP %d must not be retried", status)
		}
	}
	if maxAttempts != 3 {
		t.Fatalf("retry budget changed: %d", maxAttempts)
	}
	if transientBackoff != [2]time.Duration{300 * time.Millisecond, 600 * time.Millisecond} {
		t.Fatalf("retry backoff changed: %v", transientBackoff)
	}
}
