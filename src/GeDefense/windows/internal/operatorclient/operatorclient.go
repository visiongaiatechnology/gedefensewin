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
)

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

// Acquire performs the loopback operator handshake against baseURL. The caller
// must present the fixed broker marker; the service verifies the OS token of
// the process that owns this TCP connection. Any error is fail-closed.
func Acquire(ctx context.Context, baseURL, client string) (Session, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if client != CenterClient && client != TrayClient {
		return Session{}, errors.New("unsupported operator client")
	}
	requestID, err := randomRequestID()
	if err != nil {
		return Session{}, err
	}
	body, err := json.Marshal(struct {
		Client string `json:"client"`
	}{Client: client})
	if err != nil {
		return Session{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(baseURL, "/")+"/api/v1/session/operator", bytes.NewReader(body))
	if err != nil {
		return Session{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(BrokerHeader, brokerValue)
	request.Header.Set("X-VGT-Request-ID", requestID)
	httpClient := localhttp.NewClient(8 * time.Second)
	defer httpClient.CloseIdleConnections()
	response, err := httpClient.Do(request)
	if err != nil {
		return Session{}, fmt.Errorf("operator broker unavailable: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	limited, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return Session{}, err
	}
	if len(limited) == 0 || len(limited) > maxResponse {
		return Session{}, errors.New("operator broker response size rejected")
	}
	if response.StatusCode != http.StatusCreated {
		return Session{}, fmt.Errorf("operator broker rejected request (HTTP %d)", response.StatusCode)
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

func randomRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	value := hex.EncodeToString(raw)
	return value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32], nil
}
