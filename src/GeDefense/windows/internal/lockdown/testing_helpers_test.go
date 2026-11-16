// STATUS: PLATIN VGT SUPREME

package lockdown

// Shared test fixtures: the injected clock, the static key provider and the
// scripted phase fake. Every test in this package runs without administrator
// rights, without touching a real device, service or populated process set.

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const testEpoch = "0badc0de"

// fakeClock is a thread-safe injected clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// testKey is the deterministic 32-byte state key of the tests.
func testKey() StaticKeyProvider {
	key := make([]byte, stateKeyBytes)
	for index := range key {
		key[index] = byte(index + 1)
	}
	return StaticKeyProvider(key)
}

// newTestStore returns a store over a temporary state document.
func newTestStore(t *testing.T) (*StateStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), StateFileName)
	store, err := NewStateStore(path, testKey())
	if err != nil {
		t.Fatalf("test state store: %v", err)
	}
	return store, path
}

// testSettings returns the enabled settings with exactly the given selection.
func testSettings(selection PhaseSelection) Settings {
	settings := DefaultSettings()
	settings.Enabled = true
	settings.Phases = selection
	return settings
}

// selectionOf returns a PhaseSelection with exactly the named phases selected.
func selectionOf(names ...PhaseName) PhaseSelection {
	var selection PhaseSelection
	for _, name := range names {
		switch name {
		case PhaseNetwork:
			selection.Network = true
		case PhaseUSB:
			selection.USB = true
		case PhaseThunderbolt:
			selection.Thunderbolt = true
		case PhaseHardening:
			selection.Hardening = true
		case PhaseBrokers:
			selection.Brokers = true
		case PhaseParsers:
			selection.Parsers = true
		case PhaseSessions:
			selection.Sessions = true
		case PhaseDeviceMapper:
			selection.DeviceMapper = true
		}
	}
	return selection
}

// scriptedPhase is a configurable Phase fake. Its call counters are atomic so the
// maintenance goroutine can be exercised under -race.
type scriptedPhase struct {
	name      PhaseName
	timeout   time.Duration
	engageFn  func(context.Context) PhaseResult
	releaseFn func(context.Context) PhaseResult
	verifyFn  func(context.Context) error

	mu       sync.Mutex
	engages  int
	releases int
	verifies int
}

// appliedPhase returns a phase that reports an unverified applied isolation and
// verifies cleanly.
func appliedPhase(name PhaseName) *scriptedPhase {
	return &scriptedPhase{name: name, timeout: time.Second}
}

// failedPhase returns a phase whose engage fails.
func failedPhase(name PhaseName) *scriptedPhase {
	return &scriptedPhase{
		name: name, timeout: time.Second,
		engageFn: func(context.Context) PhaseResult {
			return PhaseResult{Phase: name, Status: PhaseFailed, Detail: "scripted failure"}
		},
	}
}

func (p *scriptedPhase) Name() PhaseName        { return p.name }
func (p *scriptedPhase) Timeout() time.Duration { return p.timeout }

func (p *scriptedPhase) Engage(ctx context.Context) PhaseResult {
	p.mu.Lock()
	p.engages++
	engage := p.engageFn
	p.mu.Unlock()
	if engage != nil {
		return engage(ctx)
	}
	return PhaseResult{Phase: p.name, Status: PhaseApplied, Detail: "scripted applied"}
}

func (p *scriptedPhase) Release(ctx context.Context) PhaseResult {
	p.mu.Lock()
	p.releases++
	release := p.releaseFn
	p.mu.Unlock()
	if release != nil {
		return release(ctx)
	}
	return PhaseResult{Phase: p.name, Status: PhaseApplied, Detail: "scripted released"}
}

func (p *scriptedPhase) Verify(ctx context.Context) error {
	p.mu.Lock()
	p.verifies++
	verify := p.verifyFn
	p.mu.Unlock()
	if verify != nil {
		return verify(ctx)
	}
	return nil
}

func (p *scriptedPhase) counts() (engages, releases, verifies int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.engages, p.releases, p.verifies
}

func (p *scriptedPhase) setEngage(fn func(context.Context) PhaseResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.engageFn = fn
}

func (p *scriptedPhase) setRelease(fn func(context.Context) PhaseResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseFn = fn
}

func (p *scriptedPhase) setVerify(fn func(context.Context) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verifyFn = fn
}

// waitFor polls condition with a bounded deadline.
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition was not reached within the bound")
}

// sampleLatchedDocument returns a valid persisted latch used by the state tests.
func sampleLatchedDocument(clock Clock) stateDocument {
	now := clock.Now()
	return stateDocument{
		Schema: stateSchema, Revision: 1, State: StateEngaged, Latched: true,
		Epoch: testEpoch, EngagedAt: now, UpdatedAt: now,
		Trigger: Trigger{ID: "trig-1", Kind: TriggerMHXCritical, DetectedAt: now},
		Action:  ActionEngage,
		Phases: []PhaseResult{{
			Action: ActionEngage, Phase: PhaseUSB, Status: PhaseApplied,
			Detail: "blocked=1", Targets: 1, StartedAt: now,
			Duration: time.Millisecond, Verified: true,
		}},
	}
}
