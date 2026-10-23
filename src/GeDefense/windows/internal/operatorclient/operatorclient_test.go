// STATUS: PLATIN
package operatorclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
