// STATUS: PLATIN VGT SUPREME

package witness

// Shared white-box test fixtures. The tests live in package witness because the
// hardening seams (injected RoundTripper, resolver, clock, sleep hook, dial guard)
// are intentionally unexported; no test seam weakens a production default.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testHostID     = "test-host-01"
	testAgent      = "5.3.0-test"
	testReceiptAt  = "2026-01-01T00:00:00Z"
	testWindowFrom = "2026-01-01T00:00:00Z"
	testWindowTo   = "2026-01-01T01:00:00Z"
)

// testNow is the fixed clock used across the package tests.
func testNow() time.Time { return time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC) }

func fixedClock(value time.Time) func() time.Time {
	return func() time.Time { return value }
}

// testDigest returns a deterministic valid lowercase hex SHA-256 digest.
func testDigest(seed string) string {
	sum := sha256.Sum256([]byte("witness-test\x00" + seed))
	return hex.EncodeToString(sum[:])
}

// newTestKeyProvider returns a static provider plus its Ed25519 private key.
func newTestKeyProvider(t *testing.T) (KeyProvider, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	outboxKey, err := GenerateOutboxKey()
	if err != nil {
		t.Fatalf("generate outbox key: %v", err)
	}
	provider, err := NewStaticKeyProvider(privateKey, outboxKey)
	if err != nil {
		t.Fatalf("new static key provider: %v", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("generated public key has an unexpected size")
	}
	return provider, privateKey
}

// testSettingsWith returns validated enabled settings pinned to publicKey and a
// fresh outbox path in the test temp directory.
func testSettingsWith(t *testing.T, publicKey ed25519.PublicKey) Settings {
	t.Helper()
	settings, err := NewSettings(Settings{
		Enabled:          true,
		Endpoint:         "https://witness.example.com",
		SPKIPin:          strings.Repeat("ab", 32),
		ReceiptPublicKey: publicKey,
		HostID:           testHostID,
		AgentVersion:     testAgent,
		PolicyGeneration: 7,
		Interval:         time.Minute,
		Timeout:          5 * time.Second,
		OutboxPath:       filepath.Join(t.TempDir(), "outbox.enc"),
	})
	if err != nil {
		t.Fatalf("new test settings: %v", err)
	}
	return settings
}

// testEngineSettings returns settings plus their key provider.
func testEngineSettings(t *testing.T) (Settings, KeyProvider) {
	t.Helper()
	provider, _ := newTestKeyProvider(t)
	return testSettingsWith(t, provider.Ed25519PublicKey()), provider
}

// testCheckpointBody is a valid unsigned checkpoint body.
func testCheckpointBody() Checkpoint {
	return Checkpoint{
		Schema:                   CheckpointSchema,
		CheckpointID:             strings.Repeat("ab", 16),
		LedgerEpoch:              1,
		Sequence:                 5,
		PreviousCheckpointSHA256: testDigest("previous"),
		LedgerTipSHA256:          testDigest("tip-5"),
		SegmentFirstSequence:     1,
		SegmentLastSequence:      5,
		EventCount:               5,
		WindowStartUTC:           testWindowFrom,
		WindowEndUTC:             testWindowTo,
		HostID:                   testHostID,
		AgentVersion:             testAgent,
		PolicyGeneration:         7,
		HashAlg:                  checkpointHashAlg,
		SignatureAlg:             checkpointSignatureAlg,
	}
}

// signedTestCheckpoint signs the default body with provider.
func signedTestCheckpoint(t *testing.T, provider KeyProvider) Checkpoint {
	t.Helper()
	signed, err := SignCheckpoint(testCheckpointBody(), provider)
	if err != nil {
		t.Fatalf("sign test checkpoint: %v", err)
	}
	return signed
}

// signedTestCheckpointAt signs a checkpoint for a sequence; callers mutate the
// returned value before re-signing when they need a different head.
func signedTestCheckpointAt(t *testing.T, provider KeyProvider, sequence uint64) Checkpoint {
	t.Helper()
	body := testCheckpointBody()
	body.CheckpointID = fmt.Sprintf("%032x", sequence)
	body.Sequence = sequence
	body.SegmentLastSequence = sequence
	body.EventCount = sequence - body.SegmentFirstSequence + 1
	body.LedgerTipSHA256 = testDigest(fmt.Sprintf("tip-%d", sequence))
	if sequence == 1 {
		body.PreviousCheckpointSHA256 = ""
	}
	signed, err := SignCheckpoint(body, provider)
	if err != nil {
		t.Fatalf("sign test checkpoint at %d: %v", sequence, err)
	}
	return signed
}

// encodeJSON marshals a value for tests.
func encodeJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return encoded
}

// testCertificate returns a self-signed certificate and its TLS connection state.
func testCertificate(t *testing.T) (*x509.Certificate, *tls.ConnectionState) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate certificate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	return certificate, state
}

// testSPKIPin returns the SPKI pin of a certificate.
func testSPKIPin(certificate *x509.Certificate) []byte {
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return digest[:]
}

// jsonHTTPResponse builds an in-memory HTTP response for fake RoundTrippers.
func jsonHTTPResponse(status int, body []byte, state *tls.ConnectionState) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       newNopReadCloser(body),
		TLS:        state,
	}
}

// nopReadCloser wraps bytes in a ReadCloser without importing io in every test.
type nopReadCloser struct{ *bytes.Reader }

func (nopReadCloser) Close() error { return nil }

func newNopReadCloser(body []byte) *nopReadCloser { return &nopReadCloser{bytes.NewReader(body)} }

// receiptEnvelope returns {"receipt": <receipt>} as the witness wire answer.
func receiptEnvelope(t *testing.T, receipt Receipt) []byte {
	t.Helper()
	return []byte(`{"receipt":` + string(encodeJSON(t, receipt)) + `}`)
}

// signedTestReceipt signs a receipt for the checkpoint with seq.
func signedTestReceipt(t *testing.T, privateKey ed25519.PrivateKey, checkpoint Checkpoint, seq uint64) Receipt {
	t.Helper()
	receipt, err := SignReceipt(Receipt{
		Schema:           ReceiptSchema,
		ReceiptID:        fmt.Sprintf("receipt-%d", seq),
		CheckpointID:     checkpoint.CheckpointID,
		CheckpointSHA256: checkpoint.CheckpointSHA256,
		WitnessSequence:  seq,
		AcceptedAtUTC:    testReceiptAt,
	}, privateKey)
	if err != nil {
		t.Fatalf("sign test receipt: %v", err)
	}
	return receipt
}

// fakeTransport is a scripted witness Transport for engine tests.
type fakeTransport struct {
	mu       sync.Mutex
	receipts []Receipt
	errs     []error
	calls    int
	closed   bool
	signKey  ed25519.PrivateKey
}

func (transport *fakeTransport) Push(_ context.Context, checkpoint Checkpoint) (Receipt, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.calls++
	if len(transport.errs) > 0 {
		err := transport.errs[0]
		transport.errs = transport.errs[1:]
		return Receipt{}, err
	}
	if len(transport.receipts) > 0 {
		receipt := transport.receipts[0]
		transport.receipts = transport.receipts[1:]
		return receipt, nil
	}
	if transport.signKey == nil {
		return Receipt{
			Schema: ReceiptSchema, ReceiptID: fmt.Sprintf("receipt-%d", transport.calls),
			CheckpointID: checkpoint.CheckpointID, CheckpointSHA256: checkpoint.CheckpointSHA256,
			WitnessSequence: uint64(transport.calls), AcceptedAtUTC: testReceiptAt,
		}, nil
	}
	seq := uint64(transport.calls)
	receipt, err := SignReceipt(Receipt{
		Schema: ReceiptSchema, ReceiptID: fmt.Sprintf("receipt-%d", seq),
		CheckpointID: checkpoint.CheckpointID, CheckpointSHA256: checkpoint.CheckpointSHA256,
		WitnessSequence: seq, AcceptedAtUTC: testReceiptAt,
	}, transport.signKey)
	if err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func (transport *fakeTransport) Close() error {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.closed = true
	return nil
}

func (transport *fakeTransport) callCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.calls
}

// fakeLedger is a scripted LedgerSource.
type fakeLedger struct {
	mu    sync.Mutex
	head  LedgerHead
	err   error
	calls int
}

func (ledger *fakeLedger) WitnessLedgerHead(_ context.Context) (LedgerHead, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.calls++
	return ledger.head, ledger.err
}

func (ledger *fakeLedger) set(head LedgerHead) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.head = head
}

func (ledger *fakeLedger) setErr(err error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.err = err
}

// testLedgerHead builds a consistent ledger head for a sequence.
func testLedgerHead(sequence uint64) LedgerHead {
	return LedgerHead{
		LedgerEpoch: 1, Sequence: sequence, TipSHA256: testDigest(fmt.Sprintf("tip-%d", sequence)),
		SegmentFirstSequence: 1, EventCount: sequence,
		WindowStartUTC: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		WindowEndUTC:   time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
	}
}

// newTestEngine builds an enabled engine with a fake ledger and transport.
func newTestEngine(t *testing.T, ledger LedgerSource, transport Transport) *Engine {
	t.Helper()
	settings, provider := testEngineSettings(t)
	engine, err := New(settings, provider, ledger,
		WithTransport(transport), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("new test engine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}
