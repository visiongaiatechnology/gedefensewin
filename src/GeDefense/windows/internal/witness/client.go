// STATUS: PLATIN VGT SUPREME

package witness

// Hardened HTTPS witness client.
//
// The client is the only component that ever sends a checkpoint off the host. It
// refuses loose configuration: https on port 443 only, no environment proxy, no
// redirects, TLS >= 1.2, a bounded round-trip timeout, a 1 MiB response cap and a
// strict JSON content-type. The server identity is pinned by the SHA-256 of its
// certificate SPKI and receipts are verified against the pinned Ed25519 receipt
// key. Pushes are idempotent (the checkpoint id is sent as Idempotency-Key) and
// retried at most three times, only for transient failures, with exponential
// backoff plus crypto/rand jitter.
//
// Error values never carry the endpoint, a header or key material: a
// *requestError exposes only a bounded classification, while errors.Is still
// reaches the underlying sentinel through Unwrap.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	clientMaxResponseBytes = 1 << 20
	clientMaxAttempts      = 3
	clientBaseBackoff      = 250 * time.Millisecond
	clientMaxBackoff       = 5 * time.Second
	clientCheckpointPath   = "/v1/checkpoint"
	clientMediaType        = "application/json"
	clientFutureSkew       = 5 * time.Minute
)

var (
	// ErrTransport marks a push that failed after the bounded retry budget.
	ErrTransport = errors.New("witness transport failed")
	// ErrResponseInvalid marks a malformed, oversized or unsupported response.
	ErrResponseInvalid = errors.New("witness response is invalid")
	// ErrRedirectRefused marks a redirect the client will never follow.
	ErrRedirectRefused = errors.New("witness redirect refused")
	// ErrReplayDetected marks a receipt sequence that does not advance.
	ErrReplayDetected = errors.New("witness receipt sequence is not monotonic")
)

// Transport is the push side the engine needs. *Client is the production
// implementation; tests inject a fake to exercise the engine without a network.
type Transport interface {
	Push(ctx context.Context, checkpoint Checkpoint) (Receipt, error)
}

// ClientSettings is the validated construction set of a Client.
type ClientSettings struct {
	// Endpoint is the absolute https base URL on port 443 of the witness.
	Endpoint string
	// SPKIPin is the server certificate SPKI pin (hex or base64, 32 raw bytes).
	SPKIPin string
	// ReceiptPublicKey is the pinned Ed25519 receipt verification key.
	ReceiptPublicKey ed25519.PublicKey
	// HostID identifies this host.
	HostID string
	// Timeout bounds one round trip. Zero selects DefaultTimeout.
	Timeout time.Duration
	// AllowPrivateDestinations explicitly permits private/link-local/loopback
	// destinations (self-hosted relays, tests). Metadata endpoints stay blocked.
	AllowPrivateDestinations bool
}

// clientConfig is the internal construction set. The injected transport, resolver,
// clock and sleep hook exist so tests exercise the production code path without a
// network and without weakening the production defaults.
type clientConfig struct {
	endpoint     *url.URL
	spkiPin      []byte
	receiptKey   ed25519.PublicKey
	hostID       string
	timeout      time.Duration
	allowPrivate bool
	transport    http.RoundTripper
	now          func() time.Time
	sleep        func(context.Context, time.Duration) error
}

// Client is the hardened witness push client. It is safe for concurrent use.
type Client struct {
	endpoint   *url.URL
	hostID     string
	receiptKey ed25519.PublicKey
	httpClient *http.Client
	now        func() time.Time
	sleep      func(context.Context, time.Duration) error

	seqMu               sync.Mutex
	lastReceiptSequence uint64
}

// requestError is the bounded classification of a failed push attempt.
type requestError struct {
	kind      string
	transient bool
	cause     error
}

func (e *requestError) Error() string { return "witness request failed: " + e.kind }

// Unwrap keeps errors.Is/As working for the underlying sentinel.
func (e *requestError) Unwrap() error { return e.cause }

func permanentFailure(kind string, cause error) error {
	return &requestError{kind: kind, transient: false, cause: cause}
}

func transientFailure(kind string, cause error) error {
	return &requestError{kind: kind, transient: true, cause: cause}
}

// isTransientFailure reports whether a push attempt may be retried.
func isTransientFailure(err error) bool {
	var classified *requestError
	if errors.As(err, &classified) {
		return classified.transient
	}
	return false
}

// NewClient builds the production client from validated settings. It fails closed
// on a missing pin, a missing receipt key, a non-443 or non-https endpoint and
// every other unsupported configuration.
func NewClient(settings ClientSettings) (*Client, error) {
	parsed, err := validateEndpoint(settings.Endpoint, settings.AllowPrivateDestinations)
	if err != nil {
		return nil, err
	}
	pin, err := ParseSPKIPin(settings.SPKIPin)
	if err != nil {
		return nil, err
	}
	if len(settings.ReceiptPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: receipt public key must be a 32-byte Ed25519 key", ErrSettingsInvalid)
	}
	if err := validateHostID(settings.HostID); err != nil {
		return nil, err
	}
	timeout := settings.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < settingsMinTimeout || timeout > settingsMaxTimeout {
		return nil, fmt.Errorf("%w: timeout must be between %s and %s", ErrSettingsInvalid, settingsMinTimeout, settingsMaxTimeout)
	}
	return newClient(clientConfig{
		endpoint: parsed, spkiPin: pin,
		receiptKey: append(ed25519.PublicKey(nil), settings.ReceiptPublicKey...),
		hostID:     settings.HostID, timeout: timeout,
		allowPrivate: settings.AllowPrivateDestinations,
	})
}

// newClient is the single constructor; production and test paths share it.
func newClient(cfg clientConfig) (*Client, error) {
	if cfg.endpoint == nil || cfg.endpoint.Scheme != "https" || cfg.endpoint.Host == "" {
		return nil, fmt.Errorf("%w: endpoint must be an absolute https URL", ErrSettingsInvalid)
	}
	if len(cfg.spkiPin) != sha256.Size {
		return nil, fmt.Errorf("%w: SPKI pin must be a SHA-256 digest", ErrSettingsInvalid)
	}
	if len(cfg.receiptKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: receipt public key is required", ErrSettingsInvalid)
	}
	if err := validateHostID(cfg.hostID); err != nil {
		return nil, err
	}
	if cfg.timeout <= 0 {
		cfg.timeout = DefaultTimeout
	}
	if cfg.now == nil {
		cfg.now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.sleep == nil {
		cfg.sleep = sleepContext
	}
	var transport http.RoundTripper
	if cfg.transport == nil {
		transport = buildHardenedTransport(cfg.spkiPin, cfg.timeout, cfg.allowPrivate)
	} else {
		transport = &pinVerifyingTransport{base: cfg.transport, pin: append([]byte(nil), cfg.spkiPin...)}
	}
	return &Client{
		endpoint: cfg.endpoint, hostID: cfg.hostID,
		receiptKey: append(ed25519.PublicKey(nil), cfg.receiptKey...),
		now:        cfg.now, sleep: cfg.sleep,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return ErrRedirectRefused
			},
		},
	}, nil
}

// Push sends one signed checkpoint to the configured witness and returns the
// verified receipt. Transient failures are retried at most clientMaxAttempts
// times; permanent trust, protocol or receipt failures are returned immediately.
func (client *Client) Push(ctx context.Context, checkpoint Checkpoint) (Receipt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err := ValidateCheckpoint(checkpoint); err != nil {
		return Receipt{}, err
	}
	body, err := EncodeCheckpoint(checkpoint)
	if err != nil {
		return Receipt{}, err
	}
	var lastErr error
	for attempt := 1; attempt <= clientMaxAttempts; attempt++ {
		if attempt > 1 {
			if err := client.sleep(ctx, client.backoff(attempt-1)); err != nil {
				return Receipt{}, err
			}
		}
		receipt, err := client.pushAttempt(ctx, checkpoint, body)
		if err == nil {
			return receipt, nil
		}
		if err := ctx.Err(); err != nil {
			return Receipt{}, err
		}
		if !isTransientFailure(err) {
			return Receipt{}, err
		}
		lastErr = err
	}
	return Receipt{}, fmt.Errorf("%w: %v", ErrTransport, lastErr)
}

// pushAttempt performs exactly one HTTP round trip and validates the answer.
func (client *Client) pushAttempt(ctx context.Context, checkpoint Checkpoint, body []byte) (Receipt, error) {
	target := strings.TrimRight(client.endpoint.String(), "/") + clientCheckpointPath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return Receipt{}, permanentFailure("request cannot be built", ErrResponseInvalid)
	}
	request.Header.Set("Content-Type", clientMediaType)
	request.Header.Set("Accept", clientMediaType)
	request.Header.Set("Idempotency-Key", checkpoint.CheckpointID)
	request.Header.Set("X-VGT-Witness-Host", client.hostID)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Receipt{}, client.classifyTransportError(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, clientMaxResponseBytes+1))
	if readErr != nil {
		return Receipt{}, transientFailure("response could not be read", readErr)
	}
	if len(data) > clientMaxResponseBytes {
		return Receipt{}, permanentFailure("response exceeds the 1 MiB bound", ErrResponseInvalid)
	}
	if err := classifyStatus(response.StatusCode); err != nil {
		return Receipt{}, err
	}
	if !isJSONMediaType(response.Header.Get("Content-Type")) {
		return Receipt{}, permanentFailure("response Content-Type is not application/json", ErrResponseInvalid)
	}
	var envelope struct {
		Receipt json.RawMessage `json:"receipt"`
	}
	if err := decodeStrictJSON(data, clientMaxResponseBytes, &envelope); err != nil || len(envelope.Receipt) == 0 {
		return Receipt{}, permanentFailure("response envelope is malformed", ErrResponseInvalid)
	}
	receipt, err := DecodeReceipt(envelope.Receipt)
	if err != nil {
		return Receipt{}, permanentFailure("receipt was rejected", ErrReceiptInvalid)
	}
	if err := VerifyReceipt(receipt, client.receiptKey); err != nil {
		return Receipt{}, permanentFailure("receipt signature does not verify", err)
	}
	if err := BindReceipt(receipt, checkpoint); err != nil {
		return Receipt{}, permanentFailure("receipt does not bind the sent checkpoint", err)
	}
	acceptedAt, ok := parseCanonicalUTC(receipt.AcceptedAtUTC)
	if !ok || acceptedAt.After(client.now().Add(clientFutureSkew)) {
		return Receipt{}, permanentFailure("receipt timestamp is not plausible", ErrReceiptInvalid)
	}
	client.seqMu.Lock()
	defer client.seqMu.Unlock()
	if receipt.WitnessSequence <= client.lastReceiptSequence {
		return Receipt{}, permanentFailure("receipt sequence does not advance", ErrReplayDetected)
	}
	client.lastReceiptSequence = receipt.WitnessSequence
	return receipt, nil
}

// classifyTransportError maps an http.Client error to a bounded classification.
func (client *Client) classifyTransportError(err error) error {
	switch {
	case errors.Is(err, ErrRedirectRefused):
		return permanentFailure("redirect refused", ErrRedirectRefused)
	case errors.Is(err, ErrSPKIPinMismatch):
		return permanentFailure("server certificate SPKI pin mismatch", ErrSPKIPinMismatch)
	case errors.Is(err, ErrDestinationRefused):
		return permanentFailure("destination is refused", ErrDestinationRefused)
	}
	var certificateErr *tls.CertificateVerificationError
	if errors.As(err, &certificateErr) {
		return permanentFailure("server certificate verification failed", ErrCertificateInvalid)
	}
	return transientFailure("network error", err)
}

// classifyStatus maps a non-2xx status to a permanent or transient failure.
func classifyStatus(status int) error {
	switch {
	case status >= 200 && status <= 299:
		return nil
	case status >= 300 && status < 400:
		return permanentFailure("redirect refused", ErrRedirectRefused)
	case status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500:
		return transientFailure(fmt.Sprintf("witness answered HTTP %d", status), ErrTransport)
	default:
		return permanentFailure(fmt.Sprintf("witness rejected the request with HTTP %d", status), ErrResponseInvalid)
	}
}

// isJSONMediaType accepts application/json with optional parameters.
func isJSONMediaType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	return mediaType == clientMediaType
}

// backoff returns exponential backoff plus crypto/rand jitter, bounded.
func (client *Client) backoff(attempt int) time.Duration {
	delay := clientBaseBackoff
	for index := 1; index < attempt; index++ {
		delay *= 2
		if delay >= clientMaxBackoff {
			delay = clientMaxBackoff
			break
		}
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return delay
	}
	jitter := time.Duration(binary.BigEndian.Uint64(raw[:]) % uint64(clientBaseBackoff))
	return delay + jitter
}

// LastReceiptSequence returns the highest verified witness receipt sequence.
func (client *Client) LastReceiptSequence() uint64 {
	client.seqMu.Lock()
	defer client.seqMu.Unlock()
	return client.lastReceiptSequence
}

// Close releases idle connections. It never panics and always succeeds.
func (client *Client) Close() error {
	client.httpClient.CloseIdleConnections()
	return nil
}

// sleepContext waits for the duration or the context, whichever comes first.
func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
