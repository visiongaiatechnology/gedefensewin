// STATUS: PLATIN
package operatorclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/localhttp"
)

const (
	// DefaultBaseURL is the fixed loopback control-plane origin.
	DefaultBaseURL = "http://127.0.0.1:17831"
	// BrokerHeader marks the local operator handshake. It is a capability
	// marker, not a secret: the server additionally verifies the calling
	// process token and rejects browsers (Origin/cookie/auth material).
	BrokerHeader = "X-VGT-Operator-Broker"
	brokerValue  = "1"
	// CenterClient requests the full operator scope set for the window host.
	CenterClient = "center-launcher"
	// TrayClient requests the read-only notification scope.
	TrayClient = "tray"
	// RefreshBefore renews a session this long before its absolute expiry.
	RefreshBefore = 2 * time.Minute
	maxResponse   = 64 << 10

	// maxAttempts bounds the whole handshake. Only transient faults (transport
	// errors and temporary 429/502/503/504 statuses) consume retries; a definite
	// 400/401/403/409 rejection is returned immediately because repeating it
	// cannot change the authorization decision and would only delay the UI.
	maxAttempts = 3
)

// transientBackoff is the bounded wait between attempts: 300 ms, then 600 ms.
var transientBackoff = [maxAttempts - 1]time.Duration{300 * time.Millisecond, 600 * time.Millisecond}

// Session is a short-lived operator session minted by the service after it
// verified the caller's Windows token. The master token file is never read by
// these clients (UI-FIND-001 / AN-FIND-004).
type Session struct {
	Token         string
	Client        string
	Scopes        []string
	Expires       time.Time
	Account       string
	Administrator bool
	Operator      bool
}

// Expired reports whether the session should be renewed before the next use.
func (s Session) Expired(now time.Time) bool {
	return s.Token == "" || now.Add(RefreshBefore).After(s.Expires)
}

// transientFailure marks a handshake error that is worth one more bounded
// attempt. It stays unwrappable so callers can still inspect the concrete cause.
type transientFailure struct{ err error }

func (t *transientFailure) Error() string { return t.err.Error() }
func (t *transientFailure) Unwrap() error { return t.err }

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// Acquire performs the loopback operator handshake against baseURL. The caller
// must present the fixed broker marker; the service verifies the OS token of
// the process that owns this TCP connection. Transient failures are retried at
// most maxAttempts times with a short bounded backoff that is abandonable via
// ctx; every definite rejection is fail-closed and returned immediately.
func Acquire(ctx context.Context, baseURL, client string) (Session, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if client != CenterClient && client != TrayClient {
		return Session{}, errors.New("unsupported operator client")
	}
	body, err := json.Marshal(struct {
		Client string `json:"client"`
	}{Client: client})
	if err != nil {
		return Session{}, err
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/api/v1/session/operator"
	httpClient := localhttp.NewClient(8 * time.Second)
	defer httpClient.CloseIdleConnections()
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		session, attemptErr := acquireOnce(ctx, httpClient, endpoint, body, client)
		if attemptErr == nil {
			return session, nil
		}
		var transient *transientFailure
		if !errors.As(attemptErr, &transient) {
			return Session{}, attemptErr
		}
		lastErr = transient.err
		if attempt == maxAttempts {
			return Session{}, lastErr
		}
		if err := waitBackoff(ctx, transientBackoff[attempt-1]); err != nil {
			return Session{}, err
		}
	}
	return Session{}, lastErr
}

// acquireOnce performs exactly one handshake attempt and classifies its result.
func acquireOnce(ctx context.Context, httpClient *http.Client, endpoint string, body []byte, client string) (Session, error) {
	requestID, err := randomRequestID()
	if err != nil {
		return Session{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Session{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(BrokerHeader, brokerValue)
	request.Header.Set("X-VGT-Request-ID", requestID)
	response, err := httpClient.Do(request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Session{}, contextErr
		}
		return Session{}, &transientFailure{err: fmt.Errorf("operator broker unavailable: %w", err)}
	}
	defer func() { _ = response.Body.Close() }()
	limited, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Session{}, contextErr
		}
		return Session{}, &transientFailure{err: fmt.Errorf("operator broker response read failed: %w", err)}
	}
	if retryableStatus(response.StatusCode) {
		return Session{}, &transientFailure{err: fmt.Errorf("operator broker temporarily unavailable (HTTP %d)", response.StatusCode)}
	}
	if response.StatusCode != http.StatusCreated {
		return Session{}, fmt.Errorf("operator broker rejected request (HTTP %d)", response.StatusCode)
	}
	if len(limited) == 0 || len(limited) > maxResponse {
		return Session{}, errors.New("operator broker response size rejected")
	}
	var payload struct {
		Token      string          `json:"token"`
		Client     string          `json:"client"`
		Scopes     []string        `json:"scopes"`
		ExpiresUTC time.Time       `json:"expiresUtc"`
		Subject    json.RawMessage `json:"subject"`
	}
	decoder := json.NewDecoder(bytes.NewReader(limited))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return Session{}, errors.New("operator broker response invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Session{}, errors.New("operator broker response contains trailing data")
	}
	if !strings.HasPrefix(payload.Token, "vgs.") || len(payload.Token) < 8 {
		return Session{}, errors.New("operator broker session token invalid")
	}
	if payload.Client != client || len(payload.Scopes) == 0 || payload.ExpiresUTC.IsZero() {
		return Session{}, errors.New("operator broker session metadata invalid")
	}
	session := Session{
		Token: payload.Token, Client: payload.Client, Scopes: payload.Scopes,
		Expires: payload.ExpiresUTC,
	}
	if len(payload.Subject) > 0 {
		var subject struct {
			Account       string `json:"account"`
			Administrator bool   `json:"administrator"`
			Operator      bool   `json:"operator"`
		}
		if err := json.Unmarshal(payload.Subject, &subject); err != nil {
			return Session{}, errors.New("operator broker subject invalid")
		}
		session.Account = subject.Account
		session.Administrator = subject.Administrator
		session.Operator = subject.Operator
	}
	return session, nil
}

// waitBackoff waits for one bounded retry delay or the caller's cancellation.
func waitBackoff(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func randomRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	value := hex.EncodeToString(raw)
	return value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32], nil
}
