// STATUS: PLATIN VGT SUPREME

package witness

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewDisabledEngineIsInert(t *testing.T) {
	settings := Settings{HostID: testHostID, AgentVersion: testAgent}
	engine, err := New(settings, nil, nil)
	if err != nil {
		t.Fatalf("New disabled engine: %v", err)
	}
	if err := engine.Start(context.Background()); err != nil {
		t.Fatalf("Start disabled engine: %v", err)
	}
	status := engine.Status()
	if status.Status != StatusDisabled || status.Enabled || status.Wired {
		t.Fatalf("disabled status is %+v", status)
	}
	if _, err := engine.CheckpointNow(context.Background()); !errors.Is(err, ErrEngineDisabled) {
		t.Fatalf("CheckpointNow error is %v", err)
	}
	if _, err := engine.PushNow(context.Background()); !errors.Is(err, ErrEngineDisabled) {
		t.Fatalf("PushNow error is %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewEnabledEngineValidation(t *testing.T) {
	settings, provider := testEngineSettings(t)
	ledger := &fakeLedger{head: testLedgerHead(1)}
	if _, err := New(settings, nil, ledger); !errors.Is(err, ErrKeyProvider) {
		t.Fatalf("nil key provider error is %v", err)
	}
	if _, err := New(settings, provider, nil); err == nil {
		t.Fatal("nil ledger source was accepted")
	}
	engine, err := New(settings, provider, ledger, WithTransport(&fakeTransport{}), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New enabled engine: %v", err)
	}
	if status := engine.Status(); status.Status != StatusUnverified || !status.Wired {
		t.Fatalf("initial status is %+v", status)
	}
	_ = engine.Close()
	if _, err := New(settings, provider, ledger, nil); err == nil {
		t.Fatal("nil option was accepted")
	}
	if _, err := New(settings, provider, ledger, WithTransport(nil)); err == nil {
		t.Fatal("nil transport option was accepted")
	}
	if _, err := New(settings, provider, ledger, WithClock(nil)); err == nil {
		t.Fatal("nil clock option was accepted")
	}
}

func TestEngineCheckpointChain(t *testing.T) {
	settings, provider := testEngineSettings(t)
	ledger := &fakeLedger{head: testLedgerHead(3)}
	engine, err := New(settings, provider, ledger, WithTransport(&fakeTransport{}), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = engine.Close() }()
	first, err := engine.CheckpointNow(context.Background())
	if err != nil {
		t.Fatalf("first checkpoint: %v", err)
	}
	if err := VerifyCheckpoint(first, provider.Ed25519PublicKey()); err != nil {
		t.Fatalf("first checkpoint does not verify: %v", err)
	}
	if first.Sequence != 3 || first.SegmentLastSequence != 3 || first.EventCount != 3 {
		t.Fatalf("first checkpoint window is %+v", first)
	}
	if first.PreviousCheckpointSHA256 != "" {
		t.Fatal("first checkpoint has a previous anchor")
	}
	if first.HostID != testHostID || first.AgentVersion != testAgent || first.PolicyGeneration != 7 {
		t.Fatalf("first checkpoint metadata is %+v", first)
	}
	if status := engine.Status(); status.OutboxDepth != 1 || status.Status != StatusUnverified {
		t.Fatalf("status after first checkpoint is %+v", status)
	}
	ledger.set(testLedgerHead(4))
	second, err := engine.CheckpointNow(context.Background())
	if err != nil {
		t.Fatalf("second checkpoint: %v", err)
	}
	if second.PreviousCheckpointSHA256 != first.CheckpointSHA256 {
		t.Fatal("second checkpoint does not link to the first")
	}
	if status := engine.Status(); status.OutboxDepth != 2 {
		t.Fatalf("outbox depth is %d", status.OutboxDepth)
	}
}

func TestEngineNoNewEvidenceAndFaults(t *testing.T) {
	settings, provider := testEngineSettings(t)
	ledger := &fakeLedger{head: testLedgerHead(5)}
	engine, err := New(settings, provider, ledger, WithTransport(&fakeTransport{}), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if _, err := engine.CheckpointNow(context.Background()); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if _, err := engine.CheckpointNow(context.Background()); !errors.Is(err, ErrNoNewEvidence) {
		t.Fatalf("unchanged head error is %v", err)
	}
	ledger.set(testLedgerHead(4))
	if _, err := engine.CheckpointNow(context.Background()); !errors.Is(err, ErrLedgerRollback) {
		t.Fatalf("rollback error is %v", err)
	}
	if status := engine.Status(); status.Status != StatusFault {
		t.Fatalf("rollback status is %s", status.Status)
	}
	if _, err := engine.CheckpointNow(context.Background()); !errors.Is(err, ErrEngineFault) {
		t.Fatalf("post-fault error is %v", err)
	}

	forkLedger := &fakeLedger{head: testLedgerHead(5)}
	forkSettings, forkProvider := testEngineSettings(t)
	forkEngine, err := New(forkSettings, forkProvider, forkLedger, WithTransport(&fakeTransport{}), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New fork engine: %v", err)
	}
	defer func() { _ = forkEngine.Close() }()
	if _, err := forkEngine.CheckpointNow(context.Background()); err != nil {
		t.Fatalf("fork engine checkpoint: %v", err)
	}
	forked := testLedgerHead(5)
	forked.TipSHA256 = testDigest("forked-tip")
	forkLedger.set(forked)
	if _, err := forkEngine.CheckpointNow(context.Background()); !errors.Is(err, ErrLedgerFork) {
		t.Fatalf("fork error is %v", err)
	}
	if status := forkEngine.Status(); status.Status != StatusFault {
		t.Fatalf("fork status is %s", status.Status)
	}

	invalidLedger := &fakeLedger{head: testLedgerHead(1)}
	invalidLedger.head.Sequence = 0
	invalidSettings, invalidProvider := testEngineSettings(t)
	invalidEngine, err := New(invalidSettings, invalidProvider, invalidLedger, WithTransport(&fakeTransport{}), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New invalid engine: %v", err)
	}
	defer func() { _ = invalidEngine.Close() }()
	if _, err := invalidEngine.CheckpointNow(context.Background()); !errors.Is(err, ErrLedgerHeadInvalid) {
		t.Fatalf("invalid head error is %v", err)
	}
	if status := invalidEngine.Status(); status.Status != StatusFault {
		t.Fatalf("invalid head status is %s", status.Status)
	}
}

func TestEnginePushConnected(t *testing.T) {
	settings, provider := testEngineSettings(t)
	ledger := &fakeLedger{head: testLedgerHead(2)}
	transport := &fakeTransport{}
	engine, err := New(settings, provider, ledger, WithTransport(transport), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = engine.Close() }()
	receipt, err := engine.PushNow(context.Background())
	if err != nil {
		t.Fatalf("PushNow: %v", err)
	}
	if receipt.WitnessSequence != 1 {
		t.Fatalf("receipt sequence is %d", receipt.WitnessSequence)
	}
	status := engine.Status()
	if status.Status != StatusConnected || status.LastReceiptSequence != 1 ||
		status.OutboxDepth != 0 || status.ConsecutiveFailures != 0 {
		t.Fatalf("connected status is %+v", status)
	}
	if transport.callCount() != 1 {
		t.Fatalf("transport calls is %d", transport.callCount())
	}
}

func TestEnginePushFailureDegradesAndKeepsEvidence(t *testing.T) {
	settings, provider := testEngineSettings(t)
	ledger := &fakeLedger{head: testLedgerHead(2)}
	transport := &fakeTransport{errs: []error{ErrTransport}}
	engine, err := New(settings, provider, ledger, WithTransport(transport), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if _, err := engine.PushNow(context.Background()); err == nil {
		t.Fatal("PushNow succeeded despite a transport failure")
	}
	status := engine.Status()
	if status.Status != StatusDegraded || status.ConsecutiveFailures != 1 {
		t.Fatalf("degraded status is %+v", status)
	}
	if status.OutboxDepth != 1 || status.OutboxFull {
		t.Fatalf("outbox state is %+v", status)
	}
	entries := engine.outbox.Pending()
	if len(entries) != 1 || entries[0].Attempts != 1 {
		t.Fatalf("pending entry after failure is %+v", entries)
	}
	if _, ok := engine.outbox.NextDue(testNow()); ok {
		t.Fatal("failed entry is immediately due again")
	}
}

func TestEngineTrustFailureFaults(t *testing.T) {
	settings, provider := testEngineSettings(t)
	ledger := &fakeLedger{head: testLedgerHead(1)}
	transport := &fakeTransport{errs: []error{ErrSPKIPinMismatch}}
	engine, err := New(settings, provider, ledger, WithTransport(transport), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if _, err := engine.PushNow(context.Background()); !errors.Is(err, ErrSPKIPinMismatch) {
		t.Fatalf("PushNow error is %v", err)
	}
	status := engine.Status()
	if status.Status != StatusFault {
		t.Fatalf("trust failure status is %s", status.Status)
	}
	if status.LastError != "witness server pin was rejected" {
		t.Fatalf("fault reason is %q", status.LastError)
	}
}

func TestEngineStatusDoesNotLeakDetails(t *testing.T) {
	settings, provider := testEngineSettings(t)
	ledger := &fakeLedger{head: testLedgerHead(1)}
	transport := &fakeTransport{errs: []error{errors.New("contact https://witness.example.com/secret")}}
	engine, err := New(settings, provider, ledger, WithTransport(transport), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if _, err := engine.PushNow(context.Background()); err == nil {
		t.Fatal("PushNow succeeded despite a transport failure")
	}
	status := engine.Status()
	if status.LastError != "witness push failed" {
		t.Fatalf("status reason is %q", status.LastError)
	}
	for _, fragment := range []string{"witness.example.com", "secret", "https://"} {
		if strings.Contains(status.LastError, fragment) {
			t.Fatalf("status leaks %q", fragment)
		}
	}
}

func TestEngineCorruptOutboxFaultsAtConstruction(t *testing.T) {
	settings, provider := testEngineSettings(t)
	if err := os.WriteFile(settings.OutboxPath, []byte("not an outbox"), 0o600); err != nil {
		t.Fatalf("write corrupt outbox: %v", err)
	}
	ledger := &fakeLedger{head: testLedgerHead(1)}
	engine, err := New(settings, provider, ledger, WithTransport(&fakeTransport{}), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New with corrupt outbox: %v", err)
	}
	defer func() { _ = engine.Close() }()
	status := engine.Status()
	if status.Status != StatusFault || status.LastError != "witness outbox is corrupt" {
		t.Fatalf("corrupt outbox status is %+v", status)
	}
	if err := engine.Start(context.Background()); !errors.Is(err, ErrEngineFault) {
		t.Fatalf("Start on corrupt engine error is %v", err)
	}
}

func TestEngineLifecycle(t *testing.T) {
	settings, provider := testEngineSettings(t)
	ledger := &fakeLedger{head: testLedgerHead(1)}
	transport := &fakeTransport{}
	engine, err := New(settings, provider, ledger, WithTransport(transport), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := engine.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for transport.callCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if transport.callCount() == 0 {
		t.Fatal("engine run loop did not push within the deadline")
	}
	if err := engine.Start(context.Background()); !errors.Is(err, ErrEngineStarted) {
		t.Fatalf("second Start error is %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !transport.closed {
		t.Fatal("Close did not close the transport")
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := engine.Start(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start with cancelled context error is %v", err)
	}
}

func TestValidateLedgerHead(t *testing.T) {
	valid := testLedgerHead(4)
	if err := validateLedgerHead(valid); err != nil {
		t.Fatalf("valid head rejected: %v", err)
	}
	cases := []struct {
		name string
		edit func(*LedgerHead)
	}{
		{"zero sequence", func(head *LedgerHead) { head.Sequence = 0 }},
		{"bad tip", func(head *LedgerHead) { head.TipSHA256 = "xyz" }},
		{"unordered segment", func(head *LedgerHead) { head.SegmentFirstSequence = 5 }},
		{"event count mismatch", func(head *LedgerHead) { head.EventCount = 2 }},
		{"reversed window", func(head *LedgerHead) { head.WindowEndUTC = head.WindowStartUTC.Add(-time.Hour) }},
		{"missing window", func(head *LedgerHead) { head.WindowStartUTC = time.Time{} }},
		{"implausible window", func(head *LedgerHead) {
			head.WindowStartUTC = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
			head.WindowEndUTC = time.Date(1970, 1, 2, 0, 0, 0, 0, time.UTC)
		}},
		{"counter overflow", func(head *LedgerHead) { head.LedgerEpoch = maxCounter + 1 }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			head := valid
			testCase.edit(&head)
			if err := validateLedgerHead(head); err == nil {
				t.Fatal("invalid ledger head accepted")
			}
		})
	}
}

func TestEngineOutboxFullDegrades(t *testing.T) {
	settings, provider := testEngineSettings(t)
	ledger := &fakeLedger{head: testLedgerHead(1)}
	engine, err := New(settings, provider, ledger, WithTransport(&fakeTransport{}), WithClock(fixedClock(testNow())))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = engine.Close() }()
	engine.outbox.mu.Lock()
	engine.outbox.bytes = OutboxMaxFileBytes
	engine.outbox.mu.Unlock()
	if _, err := engine.CheckpointNow(context.Background()); !errors.Is(err, ErrOutboxFull) {
		t.Fatalf("full outbox error is %v", err)
	}
	status := engine.Status()
	if status.Status != StatusDegraded || status.OutboxFull != true {
		t.Fatalf("full outbox status is %+v", status)
	}
	if !strings.Contains(status.LastError, "full") {
		t.Fatalf("full outbox reason is %q", status.LastError)
	}
}

func TestBoundedPushReason(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrSPKIPinMismatch, "witness server pin was rejected"},
		{ErrCertificateInvalid, "witness server certificate was rejected"},
		{ErrDestinationRefused, "witness destination was refused"},
		{ErrReceiptInvalid, "witness receipt was rejected"},
		{ErrReplayDetected, "witness receipt did not advance its sequence"},
		{ErrRedirectRefused, "witness redirect was refused"},
		{ErrResponseInvalid, "witness response was invalid"},
		{ErrTransport, "witness is unreachable"},
		{ErrCheckpointInvalid, "witness push failed"},
	}
	for _, testCase := range cases {
		if got := boundedPushReason(testCase.err); got != testCase.want {
			t.Fatalf("boundedPushReason(%v)=%q, want %q", testCase.err, got, testCase.want)
		}
	}
	if got := boundedPushReason(nil); got != "witness push failed" {
		t.Fatalf("boundedPushReason(nil)=%q", got)
	}
}

func TestDigestsEqual(t *testing.T) {
	left := testDigest("left")
	right := testDigest("right")
	if !digestsEqual(left, left) {
		t.Fatal("digestsEqual rejected identical digests")
	}
	if digestsEqual(left, right) || digestsEqual(left, "short") || digestsEqual("", "") {
		t.Fatal("digestsEqual accepted different or malformed digests")
	}
}

func TestEngineBackoff(t *testing.T) {
	engine := &Engine{settings: Settings{Interval: time.Minute}}
	if delay := engine.backoff(1); delay != engineBackoffBase {
		t.Fatalf("first backoff is %s", delay)
	}
	if delay := engine.backoff(2); delay != 2*engineBackoffBase {
		t.Fatalf("second backoff is %s", delay)
	}
	if delay := engine.backoff(32); delay != engineBackoffMax {
		t.Fatalf("capped backoff is %s", delay)
	}
	if delay := engine.backoff(0); delay != 0 {
		t.Fatalf("zero-attempt backoff is %s", delay)
	}
}
