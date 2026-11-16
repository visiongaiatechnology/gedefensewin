// STATUS: PLATIN VGT SUPREME

package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

// clientHarness bundles the pinned certificate, receipt key and sleep recorder.
type clientHarness struct {
	provider       KeyProvider
	receiptPrivate ed25519.PrivateKey
	receiptPublic  ed25519.PublicKey
	certificate    *x509.Certificate
	state          *tls.ConnectionState
	pin            []byte
	sleeps         []time.Duration
	client         *Client
}

func newClientHarness(t *testing.T) *clientHarness {
	t.Helper()
	provider, receiptPrivate := newTestKeyProvider(t)
	certificate, state := testCertificate(t)
	return &clientHarness{
		provider: provider, receiptPrivate: receiptPrivate,
		receiptPublic: provider.Ed25519PublicKey(), certificate: certificate,
		state: state, pin: testSPKIPin(certificate),
	}
}

// withTransport constructs a client over the injected RoundTripper.
func (harness *clientHarness) withTransport(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	endpoint, err := url.Parse("https://witness.example.com")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	client, err := newClient(clientConfig{
		endpoint: endpoint, spkiPin: harness.pin, receiptKey: harness.receiptPublic,
		hostID: testHostID, timeout: 5 * time.Second, transport: transport,
		now: fixedClock(testNow()),
		sleep: func(_ context.Context, duration time.Duration) error {
			harness.sleeps = append(harness.sleeps, duration)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	harness.client = client
	return client
}

// receiptTransport answers every request with a valid receipt for the checkpoint
// found in the request body.
func (harness *clientHarness) receiptTransport(t *testing.T, sequence uint64) http.RoundTripper {
	t.Helper()
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var checkpoint Checkpoint
		if err := json.NewDecoder(request.Body).Decode(&checkpoint); err != nil {
			t.Fatalf("decode pushed checkpoint: %v", err)
		}
		receipt := signedTestReceipt(t, harness.receiptPrivate, checkpoint, sequence)
		return jsonHTTPResponse(http.StatusOK, receiptEnvelope(t, receipt), harness.state), nil
	})
}

func TestNewClientValidation(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	valid := func() ClientSettings {
		return ClientSettings{
			Endpoint: "https://witness.example.com", SPKIPin: strings.Repeat("ab", 32),
			ReceiptPublicKey: publicKey, HostID: testHostID, Timeout: 5 * time.Second,
		}
	}
	if _, err := NewClient(valid()); err != nil {
		t.Fatalf("valid client settings rejected: %v", err)
	}
	cases := []struct {
		name string
		edit func(*ClientSettings)
	}{
		{"missing endpoint", func(settings *ClientSettings) { settings.Endpoint = "" }},
		{"http endpoint", func(settings *ClientSettings) { settings.Endpoint = "http://witness.example.com" }},
		{"non-443 endpoint", func(settings *ClientSettings) { settings.Endpoint = "https://witness.example.com:8443" }},
		{"missing pin", func(settings *ClientSettings) { settings.SPKIPin = "" }},
		{"bad pin", func(settings *ClientSettings) { settings.SPKIPin = "xyz" }},
		{"missing receipt key", func(settings *ClientSettings) { settings.ReceiptPublicKey = nil }},
		{"short receipt key", func(settings *ClientSettings) { settings.ReceiptPublicKey = publicKey[:16] }},
		{"bad host id", func(settings *ClientSettings) { settings.HostID = "bad host" }},
		{"timeout too small", func(settings *ClientSettings) { settings.Timeout = time.Millisecond }},
		{"private endpoint without opt-in", func(settings *ClientSettings) { settings.Endpoint = "https://127.0.0.1" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			settings := valid()
			testCase.edit(&settings)
			if _, err := NewClient(settings); !errors.Is(err, ErrSettingsInvalid) {
				t.Fatalf("NewClient error is %v, want ErrSettingsInvalid", err)
			}
		})
	}
	if _, err := NewClient(ClientSettings{
		Endpoint: "https://127.0.0.1", SPKIPin: strings.Repeat("ab", 32),
		ReceiptPublicKey: publicKey, HostID: testHostID, AllowPrivateDestinations: true,
	}); err != nil {
		t.Fatalf("explicit private destination rejected: %v", err)
	}
}

func TestClientPushHappyPath(t *testing.T) {
	harness := newClientHarness(t)
	checkpoint := signedTestCheckpointAt(t, harness.provider, 4)
	var seen *http.Request
	receiptRoundTripper := harness.receiptTransport(t, 11)
	client := harness.withTransport(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		seen = request
		return receiptRoundTripper.RoundTrip(request)
	}))
	receipt, err := client.Push(context.Background(), checkpoint)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if receipt.WitnessSequence != 11 {
		t.Fatalf("receipt sequence is %d", receipt.WitnessSequence)
	}
	if client.LastReceiptSequence() != 11 {
		t.Fatalf("LastReceiptSequence is %d", client.LastReceiptSequence())
	}
	if len(harness.sleeps) != 0 {
		t.Fatal("a successful push slept")
	}
	if seen == nil {
		t.Fatal("no request reached the transport")
	}
	if seen.Method != http.MethodPost || seen.URL.Path != clientCheckpointPath {
		t.Fatalf("request is %s %s", seen.Method, seen.URL.Path)
	}
	if seen.Header.Get("Content-Type") != clientMediaType {
		t.Fatalf("Content-Type is %q", seen.Header.Get("Content-Type"))
	}
	if seen.Header.Get("Idempotency-Key") != checkpoint.CheckpointID {
		t.Fatal("Idempotency-Key does not bind the checkpoint id")
	}
}

func TestClientPushRetriesTransientFailures(t *testing.T) {
	harness := newClientHarness(t)
	checkpoint := signedTestCheckpointAt(t, harness.provider, 1)
	calls := 0
	client := harness.withTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonHTTPResponse(http.StatusInternalServerError, []byte(`{}`), harness.state), nil
	}))
	_, err := client.Push(context.Background(), checkpoint)
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("Push error is %v, want ErrTransport", err)
	}
	if calls != clientMaxAttempts {
		t.Fatalf("transient failure made %d attempts, want %d", calls, clientMaxAttempts)
	}
	if len(harness.sleeps) != clientMaxAttempts-1 {
		t.Fatalf("retry slept %d times", len(harness.sleeps))
	}
	for index := 1; index < len(harness.sleeps); index++ {
		if harness.sleeps[index] < harness.sleeps[index-1] {
			t.Fatal("retry backoff is not non-decreasing")
		}
	}
}

func TestClientPushPermanentFailureIsNotRetried(t *testing.T) {
	harness := newClientHarness(t)
	checkpoint := signedTestCheckpointAt(t, harness.provider, 1)
	calls := 0
	client := harness.withTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonHTTPResponse(http.StatusBadRequest, []byte(`{}`), harness.state), nil
	}))
	if _, err := client.Push(context.Background(), checkpoint); !errors.Is(err, ErrResponseInvalid) {
		t.Fatalf("Push error is %v, want ErrResponseInvalid", err)
	}
	if calls != 1 {
		t.Fatalf("permanent failure made %d attempts", calls)
	}
}

func TestClientResponseHardening(t *testing.T) {
	harness := newClientHarness(t)
	checkpoint := signedTestCheckpointAt(t, harness.provider, 1)
	cases := []struct {
		name      string
		response  func() *http.Response
		want      error
		wantCalls int
	}{
		{"wrong content type", func() *http.Response {
			response := jsonHTTPResponse(http.StatusOK, receiptEnvelope(t, signedTestReceipt(t, harness.receiptPrivate, checkpoint, 1)), harness.state)
			response.Header.Set("Content-Type", "text/plain")
			return response
		}, ErrResponseInvalid, 1},
		{"oversized body", func() *http.Response {
			return jsonHTTPResponse(http.StatusOK, bytes.Repeat([]byte(" "), clientMaxResponseBytes+2), harness.state)
		}, ErrResponseInvalid, 1},
		{"malformed envelope", func() *http.Response {
			return jsonHTTPResponse(http.StatusOK, []byte(`{"receipt":{}}`), harness.state)
		}, ErrReceiptInvalid, 1},
		{"unsigned receipt", func() *http.Response {
			receipt := signedTestReceipt(t, harness.receiptPrivate, checkpoint, 1)
			receipt.Signature = ""
			return jsonHTTPResponse(http.StatusOK, receiptEnvelope(t, receipt), harness.state)
		}, ErrReceiptInvalid, 1},
		{"foreign receipt key", func() *http.Response {
			_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generate foreign key: %v", err)
			}
			return jsonHTTPResponse(http.StatusOK, receiptEnvelope(t, signedTestReceipt(t, otherPrivate, checkpoint, 1)), harness.state)
		}, ErrReceiptInvalid, 1},
		{"wrong certificate pin", func() *http.Response {
			_, otherState := testCertificate(t)
			return jsonHTTPResponse(http.StatusOK, receiptEnvelope(t, signedTestReceipt(t, harness.receiptPrivate, checkpoint, 1)), otherState)
		}, ErrSPKIPinMismatch, 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			harness.sleeps = nil
			calls := 0
			response := testCase.response
			client := harness.withTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return response(), nil
			}))
			if _, err := client.Push(context.Background(), checkpoint); !errors.Is(err, testCase.want) {
				t.Fatalf("Push error is %v, want %v", err, testCase.want)
			}
			if calls != testCase.wantCalls {
				t.Fatalf("made %d attempts, want %d", calls, testCase.wantCalls)
			}
		})
	}
}

func TestClientRejectsNonMonotonicReceipt(t *testing.T) {
	harness := newClientHarness(t)
	checkpoint := signedTestCheckpointAt(t, harness.provider, 1)
	client := harness.withTransport(t, harness.receiptTransport(t, 5))
	if _, err := client.Push(context.Background(), checkpoint); err != nil {
		t.Fatalf("first push: %v", err)
	}
	other := signedTestCheckpointAt(t, harness.provider, 2)
	if _, err := client.Push(context.Background(), other); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("replayed sequence error is %v, want ErrReplayDetected", err)
	}
}

func TestClientRefusesRedirects(t *testing.T) {
	harness := newClientHarness(t)
	checkpoint := signedTestCheckpointAt(t, harness.provider, 1)
	calls := 0
	client := harness.withTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		response := jsonHTTPResponse(http.StatusFound, []byte(`{}`), harness.state)
		response.Header.Set("Location", "https://elsewhere.example.com/v1/checkpoint")
		return response, nil
	}))
	if _, err := client.Push(context.Background(), checkpoint); !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("redirect error is %v, want ErrRedirectRefused", err)
	}
	if calls != 1 {
		t.Fatalf("redirect made %d attempts", calls)
	}
}

func TestClientProductionTransportHygiene(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	client, err := NewClient(ClientSettings{
		Endpoint: "https://witness.example.com", SPKIPin: strings.Repeat("ab", 32),
		ReceiptPublicKey: publicKey, HostID: testHostID,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("production transport is %T", client.httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("production transport honours an environment proxy")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("production transport disables certificate verification")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("production transport accepts TLS below 1.2")
	}
	if transport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("production transport does not pin the SPKI")
	}
	if err := client.httpClient.CheckRedirect(nil, nil); !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("CheckRedirect error is %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestClientPushAgainstTLSServer(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	_, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate receipt key: %v", err)
	}
	receiptPublic := receiptPrivate.Public().(ed25519.PublicKey)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var checkpoint Checkpoint
		if err := json.NewDecoder(request.Body).Decode(&checkpoint); err != nil {
			http.Error(writer, "bad checkpoint", http.StatusBadRequest)
			return
		}
		receipt := signedTestReceipt(t, receiptPrivate, checkpoint, 3)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(receiptEnvelope(t, receipt))
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	client, err := newClient(clientConfig{
		endpoint: endpoint, spkiPin: testSPKIPin(server.Certificate()),
		receiptKey: receiptPublic, hostID: testHostID, timeout: 5 * time.Second,
		transport: server.Client().Transport, now: fixedClock(testNow()),
		sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("newClient against TLS server: %v", err)
	}
	checkpoint := signedTestCheckpointAt(t, provider, 2)
	receipt, err := client.Push(context.Background(), checkpoint)
	if err != nil {
		t.Fatalf("Push against TLS server: %v", err)
	}
	if receipt.WitnessSequence != 3 {
		t.Fatalf("receipt sequence is %d", receipt.WitnessSequence)
	}
}

func TestDialGuardRefusesForbiddenDestinations(t *testing.T) {
	guard := &dialGuard{
		dialer:   &net.Dialer{Timeout: time.Second},
		resolver: net.DefaultResolver,
	}
	cases := []struct {
		name         string
		address      string
		allowPrivate bool
	}{
		{"loopback", "127.0.0.1:443", false},
		{"private", "10.1.2.3:443", false},
		{"link local", "169.254.1.1:443", false},
		{"metadata with opt-in", "169.254.169.254:443", true},
		{"aliyun metadata with opt-in", "100.100.100.200:443", true},
		{"localhost", "localhost:443", false},
		{"wrong port", "203.0.113.1:8443", true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			guard.allowPrivate = testCase.allowPrivate
			if _, err := guard.DialContext(context.Background(), "tcp", testCase.address); !errors.Is(err, ErrDestinationRefused) {
				t.Fatalf("DialContext error is %v, want ErrDestinationRefused", err)
			}
		})
	}
}

func TestHardenedTransportConfiguration(t *testing.T) {
	pin := []byte("0123456789abcdef0123456789abcdef")
	transport := buildHardenedTransport(pin, 7*time.Second, false)
	if transport.Proxy != nil {
		t.Fatal("hardened transport honours an environment proxy")
	}
	if transport.DialContext == nil {
		t.Fatal("hardened transport has no guarded dialer")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify ||
		transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("hardened transport does not enforce TLS verification and TLS >= 1.2")
	}
	if transport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("hardened transport does not pin the SPKI")
	}
	if transport.TLSHandshakeTimeout != 7*time.Second || transport.ResponseHeaderTimeout != 7*time.Second {
		t.Fatal("hardened transport timeouts are not the configured deadline")
	}
	if transport.MaxIdleConns != 2 {
		t.Fatalf("MaxIdleConns is %d", transport.MaxIdleConns)
	}
}

func TestSleepContext(t *testing.T) {
	if err := sleepContext(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("sleepContext returned %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(cancelled, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("sleepContext on a cancelled context returned %v", err)
	}
}

func TestClassifyTransportError(t *testing.T) {
	harness := newClientHarness(t)
	client := harness.withTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, ErrTransport
	}))
	certificateError := &tls.CertificateVerificationError{Err: errors.New("x509: unknown authority")}
	classified := client.classifyTransportError(certificateError)
	if !errors.Is(classified, ErrCertificateInvalid) || isTransientFailure(classified) {
		t.Fatalf("certificate error classification is %v", classified)
	}
	if classified := client.classifyTransportError(ErrSPKIPinMismatch); !errors.Is(classified, ErrSPKIPinMismatch) ||
		isTransientFailure(classified) {
		t.Fatalf("pin mismatch classification is %v", classified)
	}
	if classified := client.classifyTransportError(ErrRedirectRefused); !errors.Is(classified, ErrRedirectRefused) ||
		isTransientFailure(classified) {
		t.Fatalf("redirect classification is %v", classified)
	}
	if classified := client.classifyTransportError(ErrDestinationRefused); !errors.Is(classified, ErrDestinationRefused) ||
		isTransientFailure(classified) {
		t.Fatalf("destination classification is %v", classified)
	}
	if classified := client.classifyTransportError(errors.New("temporary network failure")); !isTransientFailure(classified) {
		t.Fatalf("network classification is %v", classified)
	}
}
