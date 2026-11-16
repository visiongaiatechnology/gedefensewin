// STATUS: PLATIN VGT SUPREME

package witness

// Witness engine lifecycle.
//
// New builds the engine from validated Settings, a KeyProvider and a narrow
// LedgerSource; it performs no network I/O. Start(ctx) owns exactly one goroutine:
// it creates a signed checkpoint for the authenticated ledger head, appends it to
// the bounded outbox and pushes due entries. Close cancels the run context and
// joins the goroutine; no goroutine outlives Close.
//
// The engine never mutates global state and never imports the evidence package:
// the application adapts its ledger to LedgerSource. Failure direction is fail
// closed: a ledger rollback/fork, a bad ledger head, a corrupt outbox or a trust
// failure puts the engine into FAULT and stops pushes; an unreachable witness only
// degrades. Status is honest: DISABLED (inert), UNVERIFIED (no verified receipt
// yet), CONNECTED (last operation produced a verified receipt), DEGRADED (a
// failure or the outbox is at its bound), FAULT (fail-closed stop).

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	engineMaxCyclePushes = 4
	engineBackoffBase    = 30 * time.Second
	engineBackoffMax     = time.Hour
)

var (
	// ErrEngineDisabled marks an operation on an inert (disabled) engine.
	ErrEngineDisabled = errors.New("witness engine is disabled")
	// ErrEngineStarted marks a second Start on a running engine.
	ErrEngineStarted = errors.New("witness engine is already started")
	// ErrEngineFault marks an operation on a fail-closed engine.
	ErrEngineFault = errors.New("witness engine is in the FAULT state")
	// ErrNoNewEvidence marks a ledger head that did not advance since the last
	// checkpoint; no new checkpoint is created.
	ErrNoNewEvidence = errors.New("witness ledger head did not advance")
)

// engineOptions carries the test/integration injection points.
type engineOptions struct {
	transport Transport
	now       func() time.Time
}

// Option configures optional Engine seams.
type Option func(*engineOptions) error

// WithTransport injects the push transport (tests, alternative transports). The
// production default is the hardened HTTPS *Client.
func WithTransport(transport Transport) Option {
	return func(options *engineOptions) error {
		if transport == nil {
			return errors.New("witness transport option requires a transport")
		}
		options.transport = transport
		return nil
	}
}

// WithClock injects the time source. The default is time.Now().UTC().
func WithClock(now func() time.Time) Option {
	return func(options *engineOptions) error {
		if now == nil {
			return errors.New("witness clock option requires a function")
		}
		options.now = now
		return nil
	}
}

// Engine is the witness lifecycle owner. It is safe for concurrent status reads
// and operator calls; checkpoint/push cycles are serialised.
type Engine struct {
	settings  Settings
	keys      KeyProvider
	ledger    LedgerSource
	outbox    *Outbox
	transport Transport
	now       func() time.Time

	mu                  sync.Mutex
	cycleMu             sync.Mutex
	started             bool
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	faultReason         string
	lastCheckpoint      *Checkpoint
	lastReceiptSequence uint64
	failures            int
	lastError           string
}

// New builds the engine. It opens and authenticates the outbox when the witness is
// enabled but performs no network I/O and starts no goroutine. A corrupt outbox
// yields a constructible engine in FAULT so the application can report it; any
// other configuration or file-system error is returned to the caller.
func New(settings Settings, keyProvider KeyProvider, ledger LedgerSource, opts ...Option) (*Engine, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	options := engineOptions{now: func() time.Time { return time.Now().UTC() }}
	for _, option := range opts {
		if option == nil {
			return nil, errors.New("witness engine option is nil")
		}
		if err := option(&options); err != nil {
			return nil, err
		}
	}
	engine := &Engine{
		settings: settings, keys: keyProvider, ledger: ledger,
		transport: options.transport, now: options.now,
	}
	if !settings.Enabled {
		return engine, nil
	}
	if keyProvider == nil {
		return nil, fmt.Errorf("%w: an enabled witness requires a key provider", ErrKeyProvider)
	}
	publicKey := keyProvider.Ed25519PublicKey()
	if len(publicKey) != ed25519.PublicKeySize || PublicKeyFingerprint(publicKey) == "" {
		return nil, fmt.Errorf("%w: checkpoint public key is invalid", ErrKeyProvider)
	}
	outboxKey := keyProvider.OutboxKey()
	if len(outboxKey) != outboxKeyBytes {
		return nil, fmt.Errorf("%w: outbox key must be %d bytes", ErrKeyProvider, outboxKeyBytes)
	}
	if ledger == nil {
		return nil, errors.New("an enabled witness requires a ledger source")
	}
	outbox, err := OpenOutbox(settings.OutboxPath, outboxKey, settings.HostID)
	if err != nil {
		if outbox == nil || !outbox.Corrupt() {
			return nil, err
		}
		engine.outbox = outbox
		engine.faultReason = "witness outbox is corrupt"
		return engine, nil
	}
	engine.outbox = outbox
	// The outbox and the engine share one clock, so a checkpoint appended by a
	// cycle is due immediately in that cycle.
	outbox.now = engine.now
	if checkpoint, ok := outbox.LastCheckpoint(); ok {
		anchor := checkpoint
		engine.lastCheckpoint = &anchor
	}
	if engine.transport == nil {
		client, err := NewClient(ClientSettings{
			Endpoint: settings.Endpoint, SPKIPin: settings.SPKIPin,
			ReceiptPublicKey: settings.ReceiptPublicKey, HostID: settings.HostID,
			Timeout: settings.Timeout, AllowPrivateDestinations: settings.AllowPrivateDestinations,
		})
		if err != nil {
			return nil, err
		}
		engine.transport = client
	}
	return engine, nil
}

// Start launches the single engine goroutine. A disabled engine stays inert and
// Start is a successful no-op; a FAULT engine refuses to start.
func (e *Engine) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("witness engine start requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	if !e.settings.Enabled {
		e.mu.Unlock()
		return nil
	}
	if e.faultReason != "" {
		reason := e.faultReason
		e.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrEngineFault, reason)
	}
	if e.started {
		e.mu.Unlock()
		return ErrEngineStarted
	}
	runCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.started = true
	e.wg.Add(1)
	e.mu.Unlock()
	go e.run(runCtx)
	return nil
}

// Close cancels the run context, joins the engine goroutine and releases idle
// connections. It is idempotent.
func (e *Engine) Close() error {
	e.mu.Lock()
	cancel := e.cancel
	e.cancel = nil
	e.started = false
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	e.wg.Wait()
	if closer, ok := e.transport.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	return nil
}

// run is the only engine goroutine. It always exits when ctx is cancelled.
func (e *Engine) run(ctx context.Context) {
	defer e.wg.Done()
	e.cycle(ctx)
	interval := e.settings.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.cycle(ctx)
		}
	}
}

// cycle runs one checkpoint/push cycle.
func (e *Engine) cycle(ctx context.Context) {
	e.cycleMu.Lock()
	defer e.cycleMu.Unlock()
	_, _ = e.checkpointLocked(ctx)
	e.pushPendingLocked(ctx)
}

// CheckpointNow creates and queues one signed checkpoint on operator request. It
// performs no network I/O.
func (e *Engine) CheckpointNow(ctx context.Context) (Checkpoint, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	e.cycleMu.Lock()
	defer e.cycleMu.Unlock()
	return e.checkpointLocked(ctx)
}

// PushNow creates a checkpoint when the queue is empty, then pushes the oldest
// due entry and returns its verified receipt.
func (e *Engine) PushNow(ctx context.Context) (Receipt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	e.cycleMu.Lock()
	defer e.cycleMu.Unlock()
	if _, err := e.checkpointLocked(ctx); err != nil && !errors.Is(err, ErrNoNewEvidence) {
		return Receipt{}, err
	}
	entries := e.outbox.Pending()
	if len(entries) == 0 {
		return Receipt{}, ErrOutboxEntryMissing
	}
	return e.pushEntry(ctx, entries[0])
}

// checkpointLocked builds, signs and queues one checkpoint. The caller holds
// cycleMu.
func (e *Engine) checkpointLocked(ctx context.Context) (Checkpoint, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !e.settings.Enabled {
		return Checkpoint{}, ErrEngineDisabled
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	e.mu.Lock()
	fault := e.faultReason
	e.mu.Unlock()
	if fault != "" {
		return Checkpoint{}, fmt.Errorf("%w: %s", ErrEngineFault, fault)
	}
	if e.outbox == nil || e.transport == nil {
		return Checkpoint{}, fmt.Errorf("%w: witness runtime is not wired", ErrEngineFault)
	}
	if e.outbox.Full() {
		e.setLastError("witness outbox is full; no new checkpoint is created")
		return Checkpoint{}, ErrOutboxFull
	}
	head, err := e.ledger.WitnessLedgerHead(ctx)
	if err != nil {
		e.mu.Lock()
		e.failures++
		e.lastError = "witness ledger head is unavailable"
		e.mu.Unlock()
		return Checkpoint{}, fmt.Errorf("witness ledger head: %w", err)
	}
	if err := validateLedgerHead(head); err != nil {
		e.enterFault("witness ledger head violates its contract")
		return Checkpoint{}, fmt.Errorf("%w: %v", ErrLedgerHeadInvalid, err)
	}
	e.mu.Lock()
	last := e.lastCheckpoint
	e.mu.Unlock()
	if last != nil {
		switch {
		case head.LedgerEpoch < last.LedgerEpoch,
			head.LedgerEpoch == last.LedgerEpoch && head.Sequence < last.Sequence:
			e.enterFault("witness ledger rollback detected")
			return Checkpoint{}, ErrLedgerRollback
		case head.LedgerEpoch == last.LedgerEpoch && head.Sequence == last.Sequence:
			if !digestsEqual(head.TipSHA256, last.LedgerTipSHA256) {
				e.enterFault("witness ledger fork detected")
				return Checkpoint{}, ErrLedgerFork
			}
			return Checkpoint{}, ErrNoNewEvidence
		}
	}
	checkpointID, err := NewCheckpointID()
	if err != nil {
		e.enterFault("witness checkpoint id generation failed")
		return Checkpoint{}, err
	}
	previous := ""
	if last != nil {
		previous = last.CheckpointSHA256
	}
	checkpoint := Checkpoint{
		Schema: CheckpointSchema, CheckpointID: checkpointID,
		LedgerEpoch: head.LedgerEpoch, Sequence: head.Sequence,
		PreviousCheckpointSHA256: previous, LedgerTipSHA256: head.TipSHA256,
		SegmentFirstSequence: head.SegmentFirstSequence, SegmentLastSequence: head.Sequence,
		EventCount:     head.EventCount,
		WindowStartUTC: head.WindowStartUTC.UTC().Format(checkpointTimestampLayout),
		WindowEndUTC:   head.WindowEndUTC.UTC().Format(checkpointTimestampLayout),
		HostID:         e.settings.HostID, AgentVersion: e.settings.AgentVersion,
		PolicyGeneration: e.settings.PolicyGeneration,
		HashAlg:          checkpointHashAlg, SignatureAlg: checkpointSignatureAlg,
	}
	signed, err := SignCheckpoint(checkpoint, e.keys)
	if err != nil {
		e.enterFault("witness checkpoint could not be signed")
		return Checkpoint{}, err
	}
	if _, err := e.outbox.Append(signed); err != nil {
		switch {
		case errors.Is(err, ErrOutboxFull):
			e.setLastError("witness outbox is full; no new checkpoint is created")
			return Checkpoint{}, err
		case errors.Is(err, ErrOutboxDuplicate):
			return Checkpoint{}, ErrNoNewEvidence
		default:
			e.enterFault("witness outbox write failed")
			return Checkpoint{}, err
		}
	}
	e.mu.Lock()
	anchor := signed
	e.lastCheckpoint = &anchor
	e.mu.Unlock()
	return signed, nil
}

// pushPendingLocked drains a bounded number of due entries. A failed push ends
// the cycle; the queue keeps the evidence and the next ticker retries.
func (e *Engine) pushPendingLocked(ctx context.Context) {
	for processed := 0; processed < engineMaxCyclePushes; processed++ {
		e.mu.Lock()
		fault := e.faultReason
		e.mu.Unlock()
		if fault != "" {
			return
		}
		entry, ok := e.outbox.NextDue(e.now())
		if !ok {
			return
		}
		if _, err := e.pushEntry(ctx, entry); err != nil {
			return
		}
	}
}

// pushEntry performs one push and removes the entry only after a verified
// receipt. It is idempotent: a crash before the acknowledgement leaves the
// checkpoint queued and the next push resends the same checkpoint id.
func (e *Engine) pushEntry(ctx context.Context, entry OutboxEntry) (Receipt, error) {
	receipt, err := e.transport.Push(ctx, entry.Checkpoint)
	if err != nil {
		e.handlePushFailure(entry, err)
		return Receipt{}, err
	}
	if err := e.outbox.Ack(entry.LocalSequence); err != nil {
		if errors.Is(err, ErrOutboxCorrupt) {
			e.enterFault("witness outbox is corrupt")
		}
		e.setLastError("witness outbox acknowledgement could not be persisted")
		return Receipt{}, err
	}
	e.mu.Lock()
	e.failures = 0
	e.lastReceiptSequence = receipt.WitnessSequence
	e.lastError = ""
	e.mu.Unlock()
	return receipt, nil
}

// handlePushFailure persists the attempt bookkeeping and classifies the failure.
// Trust failures are fail-closed (FAULT); transient failures degrade.
func (e *Engine) handlePushFailure(entry OutboxEntry, err error) {
	permanent := errors.Is(err, ErrSPKIPinMismatch) || errors.Is(err, ErrCertificateInvalid) ||
		errors.Is(err, ErrDestinationRefused) || errors.Is(err, ErrReceiptInvalid) ||
		errors.Is(err, ErrCheckpointInvalid) || errors.Is(err, ErrReplayDetected) ||
		errors.Is(err, ErrRedirectRefused)
	attempts := entry.Attempts + 1
	nextAttempt := e.now().Add(e.backoff(attempts))
	if recordErr := e.outbox.RecordAttempt(entry.LocalSequence, attempts, nextAttempt); recordErr != nil {
		if errors.Is(recordErr, ErrOutboxCorrupt) {
			e.enterFault("witness outbox is corrupt")
		}
	}
	reason := boundedPushReason(err)
	e.mu.Lock()
	e.failures++
	e.lastError = reason
	e.mu.Unlock()
	if permanent {
		e.enterFault(reason)
	}
}

// backoff returns the exponential retry delay for a failed push, capped.
func (e *Engine) backoff(attempts int) time.Duration {
	if attempts <= 0 {
		return 0
	}
	delay := engineBackoffBase
	for index := 1; index < attempts && index < 8; index++ {
		if delay >= engineBackoffMax/2 {
			return engineBackoffMax
		}
		delay *= 2
	}
	if delay > engineBackoffMax {
		return engineBackoffMax
	}
	return delay
}

// enterFault transitions the engine into the fail-closed FAULT state once.
func (e *Engine) enterFault(reason string) {
	e.mu.Lock()
	if e.faultReason == "" {
		e.faultReason = reason
	}
	e.mu.Unlock()
}

// setLastError records a bounded operator-visible reason.
func (e *Engine) setLastError(reason string) {
	e.mu.Lock()
	e.lastError = reason
	e.mu.Unlock()
}
