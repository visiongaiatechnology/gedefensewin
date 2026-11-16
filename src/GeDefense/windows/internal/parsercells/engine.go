// STATUS: DIAMANT VGT SUPREME
//go:build windows

package parsercells

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Engine bounds the number of concurrently active cells, enforces a total
// lifetime independent of any single cell budget, reclaims orphaned kernel
// objects from a previous crashed process and exposes honest status counters.
// It owns exactly one timer goroutine, which Close stops and joins; there is no
// global mutable state.
type Engine struct {
	mu sync.Mutex

	root          string
	profiles      map[string]Profile
	profileNames  []string
	maxActive     int
	totalLifetime time.Duration
	sweepInterval time.Duration
	clock         func() time.Time
	ledger        Ledger
	platform      platform
	cellFactory   cellFactory

	capacity chan struct{}
	active   map[string]cellHandle
	closed   bool

	stop chan struct{}
	done chan struct{}

	counters        EngineCounters
	orphansReclamed uint64
	lastError       string
	lastErrorUTC    time.Time
}

// EngineCounters are monotonic, bounded engine counters. They cannot grow
// without limit because no per-event history is retained.
type EngineCounters struct {
	CellsCreated  uint64 `json:"cellsCreated"`
	CellsBurned   uint64 `json:"cellsBurned"`
	CellsFailed   uint64 `json:"cellsFailed"`
	Saturations   uint64 `json:"saturations"`
	Cancellations uint64 `json:"cancellations"`
	LifetimeBurns uint64 `json:"lifetimeBurns"`
}

// Status is the honest engine state for the control plane.
type Status struct {
	Enabled          bool           `json:"enabled"`
	Closed           bool           `json:"closed"`
	TickerRunning    bool           `json:"tickerRunning"`
	Root             string         `json:"root"`
	Profiles         []string       `json:"profiles"`
	Active           int            `json:"active"`
	MaxActive        int            `json:"maxActive"`
	TotalLifetimeMS  int64          `json:"totalLifetimeMs"`
	SweepIntervalMS  int64          `json:"sweepIntervalMs"`
	OrphansReclaimed uint64         `json:"orphansReclaimed"`
	Counters         EngineCounters `json:"counters"`
	LastError        string         `json:"lastError,omitempty"`
	LastErrorUTC     time.Time      `json:"lastErrorUtc,omitempty"`
}

// cellHandle is the engine-facing cell contract. Tests inject a fake.
type cellHandle interface {
	ID() string
	Status() CellStatus
	Create(ctx context.Context, profile Profile, input []byte, executable string) (Result, error)
	Freeze(ctx context.Context) error
	Burn(ctx context.Context) error
}

// cellFactory creates a cell. Production uses NewCell; tests inject a fake.
type cellFactory func(options CellOptions) (cellHandle, error)

// EngineOptions configures the manager.
type EngineOptions struct {
	// Root is the absolute, canonical staging root.
	Root string
	// Profiles are the validated parser profiles. At least one is required.
	Profiles []Profile
	// MaxActive bounds concurrent cells. Defaults to DefaultMaxActive.
	MaxActive int
	// TotalLifetime is the hard engine-level lifetime of a cell. Defaults to
	// 90 seconds; it is bounded.
	TotalLifetime time.Duration
	// SweepInterval is the lifetime-enforcer tick. Defaults to one second.
	SweepInterval time.Duration
	// Ledger optionally records engine-level evidence.
	Ledger Ledger
	// Clock is injectable for tests.
	Clock func() time.Time
	// platform is injectable for tests; nil uses the Windows adapters.
	platform platform
	// factory is injectable for tests; nil uses NewCell.
	factory cellFactory
}

// Bounds for the engine configuration.
const (
	// HardMinTotalLifetime is the shortest accepted engine lifetime.
	HardMinTotalLifetime = 1 * time.Second
	// HardMaxTotalLifetime is the longest accepted engine lifetime.
	HardMaxTotalLifetime = 15 * time.Minute
	// DefaultTotalLifetime is the default engine-level cell lifetime.
	DefaultTotalLifetime = 90 * time.Second
	// DefaultSweepInterval is the default lifetime tick.
	DefaultSweepInterval = time.Second
	// engineBurnTimeout bounds every synchronous engine cleanup call.
	engineBurnTimeout = 15 * time.Second
	// expiringGrace allows a finished cell to be burned by its owner before the
	// enforcer steps in.
	expiringGrace = 10 * time.Second
)

// NewEngine validates the configuration, reclaims orphaned kernel objects from
// a previous process and starts the lifecycle ticker.
func NewEngine(ctx context.Context, options EngineOptions) (*Engine, error) {
	if err := ValidateStagingRoot(options.Root); err != nil {
		return nil, &Error{Op: "engine.new", Kind: ErrStagingUnsafe, Detail: err.Error()}
	}
	maxActive := options.MaxActive
	if maxActive == 0 {
		maxActive = DefaultMaxActive
	}
	if maxActive < 1 || maxActive > HardMaxActive {
		return nil, &Error{Op: "engine.new", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("max active %d outside [1,%d]", maxActive, HardMaxActive)}
	}
	lifetime := options.TotalLifetime
	if lifetime == 0 {
		lifetime = DefaultTotalLifetime
	}
	if lifetime < HardMinTotalLifetime || lifetime > HardMaxTotalLifetime {
		return nil, &Error{Op: "engine.new", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("total lifetime %s outside [%s,%s]", lifetime, HardMinTotalLifetime, HardMaxTotalLifetime)}
	}
	interval := options.SweepInterval
	if interval == 0 {
		interval = DefaultSweepInterval
	}
	if interval < 10*time.Millisecond || interval > 30*time.Second {
		return nil, &Error{Op: "engine.new", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("sweep interval %s outside [10ms,30s]", interval)}
	}
	if len(options.Profiles) == 0 {
		return nil, &Error{Op: "engine.new", Kind: ErrInvalidProfile, Detail: "at least one parser profile is required"}
	}
	if len(options.Profiles) > HardMaxProfiles {
		return nil, &Error{Op: "engine.new", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("%d profiles exceeds %d", len(options.Profiles), HardMaxProfiles)}
	}
	profiles := make(map[string]Profile, len(options.Profiles))
	names := make([]string, 0, len(options.Profiles))
	for _, profile := range options.Profiles {
		if err := profile.Validate(); err != nil {
			return nil, err
		}
		if _, duplicate := profiles[profile.Name]; duplicate {
			return nil, &Error{Op: "engine.new", Kind: ErrInvalidProfile,
				Detail: "duplicate profile " + profile.Name}
		}
		profiles[profile.Name] = profile
		names = append(names, profile.Name)
	}
	sort.Strings(names)
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	adapter := options.platform
	if adapter == nil {
		adapter = newPlatform(options.Root)
	}
	if err := adapter.PrepareRoot(); err != nil {
		return nil, err
	}
	factory := options.factory
	if factory == nil {
		factory = func(cellOptions CellOptions) (cellHandle, error) {
			return NewCell(cellOptions)
		}
	}
	engine := &Engine{
		root:          options.Root,
		profiles:      profiles,
		profileNames:  names,
		maxActive:     maxActive,
		totalLifetime: lifetime,
		sweepInterval: interval,
		clock:         clock,
		ledger:        options.Ledger,
		platform:      adapter,
		cellFactory:   factory,
		capacity:      make(chan struct{}, maxActive),
		active:        make(map[string]cellHandle, maxActive),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	if err := engine.reclaimOrphans(ctx); err != nil {
		return nil, err
	}
	go engine.sweepLoop()
	return engine, nil
}

// reclaimOrphans deletes AppContainer profiles and staging directories left by a
// previous crashed process before any new cell is admitted.
func (e *Engine) reclaimOrphans(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("parsercells: engine startup canceled: %w", err)
	}
	records, err := e.platform.ScanOrphans(maxOrphanRecords)
	if err != nil {
		return fmt.Errorf("parsercells: orphan scan: %w", err)
	}
	var reclaimErrors []error
	for _, record := range records {
		if err := e.platform.ReclaimOrphan(ctx, record); err != nil {
			reclaimErrors = append(reclaimErrors, err)
			continue
		}
		e.mu.Lock()
		e.orphansReclamed++
		e.mu.Unlock()
		e.record("parser-cell.orphan.reclaimed", "reclaimed orphaned cell "+record.CellID, "RECLAIMED")
	}
	if joined := errors.Join(reclaimErrors...); joined != nil {
		e.setLastError(joined)
		return fmt.Errorf("parsercells: orphan reclamation incomplete: %w", joined)
	}
	return nil
}

// Submit runs one parser profile against one input with bounded concurrency.
// Every accepted submission is burned before Submit returns, including on
// cancellation, because a cell is never left for garbage collection.
func (e *Engine) Submit(ctx context.Context, profileName string, input []byte, executable string) (Result, error) {
	var zero Result
	profile, found := e.profiles[profileName]
	if !found {
		return zero, &Error{Op: "engine.submit", Kind: ErrInvalidProfile, Detail: "unknown profile " + sanitizeText(profileName)}
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("parsercells: submit canceled: %w", err)
	}
	select {
	case e.capacity <- struct{}{}:
	case <-ctx.Done():
		return zero, fmt.Errorf("parsercells: submit canceled: %w", ctx.Err())
	default:
		e.mu.Lock()
		e.counters.Saturations++
		e.mu.Unlock()
		e.record("parser-cell.saturated", "cell capacity exhausted", "REFUSED")
		return zero, ErrSaturated
	}
	defer func() { <-e.capacity }()

	cellID, err := newCellID()
	if err != nil {
		return zero, err
	}
	cell, err := e.cellFactory(CellOptions{
		ID:       cellID,
		Root:     e.root,
		Ledger:   e.ledger,
		Clock:    e.clock,
		platform: e.platform,
	})
	if err != nil {
		e.setLastError(err)
		return zero, err
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return zero, ErrClosed
	}
	e.active[cell.ID()] = cell
	e.counters.CellsCreated++
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.active, cell.ID())
		e.mu.Unlock()
	}()
	e.record("parser-cell.create", "created cell "+cell.ID()+" profile "+profileName, "REQUESTED")

	result, createErr := cell.Create(ctx, profile, input, executable)
	burnErr := e.burnCell(cell)
	if createErr != nil {
		e.mu.Lock()
		e.counters.CellsFailed++
		e.mu.Unlock()
		e.setLastError(createErr)
		e.record("parser-cell.submit.result", "cell "+cell.ID()+" run failed: "+sanitizeText(createErr.Error()), "FAILED")
		return result, createErr
	}
	if burnErr != nil {
		e.mu.Lock()
		e.counters.CellsFailed++
		e.mu.Unlock()
		e.setLastError(burnErr)
		return result, burnErr
	}
	e.mu.Lock()
	e.counters.CellsBurned++
	e.mu.Unlock()
	return result, nil
}

// burnCell performs bounded cleanup for one cell.
func (e *Engine) burnCell(cell cellHandle) error {
	burnContext, cancel := context.WithTimeout(context.Background(), engineBurnTimeout)
	defer cancel()
	return cell.Burn(burnContext)
}

// sweepLoop is the single engine goroutine. It exits when stop is closed.
func (e *Engine) sweepLoop() {
	defer close(e.done)
	ticker := time.NewTicker(e.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-ticker.C:
			e.sweep()
		}
	}
}

// sweep enforces the engine-level total lifetime and expires finished cells.
func (e *Engine) sweep() {
	now := e.clock().UTC()
	e.mu.Lock()
	candidates := make([]cellHandle, 0, len(e.active))
	for _, cell := range e.active {
		status := cell.Status()
		switch status.State {
		case StateSpawned, StateIsolated:
			if now.Sub(status.CreatedUTC) > e.totalLifetime {
				candidates = append(candidates, cell)
			}
		case StateExpiring:
			if now.Sub(status.UpdatedUTC) > expiringGrace {
				candidates = append(candidates, cell)
			}
		}
	}
	if len(candidates) > 0 {
		e.counters.LifetimeBurns += uint64(len(candidates))
	}
	e.mu.Unlock()
	if len(candidates) == 0 {
		return
	}
	for _, cell := range candidates {
		stopContext, cancel := context.WithTimeout(context.Background(), engineBurnTimeout)
		_ = cell.Freeze(stopContext)
		if err := cell.Burn(stopContext); err != nil {
			e.setLastError(err)
			e.record("parser-cell.sweep", "lifetime burn failed for cell "+cell.ID(), "FAILED")
		} else {
			e.record("parser-cell.sweep", "lifetime burn completed for cell "+cell.ID(), "BURNED")
		}
		cancel()
	}
}

// Close stops the ticker, waits for it and burns every still-active cell.
func (e *Engine) Close(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	close(e.stop)
	pending := make([]cellHandle, 0, len(e.active))
	for _, cell := range e.active {
		pending = append(pending, cell)
	}
	e.mu.Unlock()

	select {
	case <-e.done:
	case <-ctx.Done():
		return fmt.Errorf("parsercells: engine close canceled while stopping ticker: %w", ctx.Err())
	}
	var closeErrors []error
	for _, cell := range pending {
		if err := e.burnCell(cell); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	if joined := errors.Join(closeErrors...); joined != nil {
		e.setLastError(joined)
		return joined
	}
	return nil
}

// Status returns a bounded snapshot.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := Status{
		Enabled:          true,
		Closed:           e.closed,
		TickerRunning:    !e.closed,
		Root:             e.root,
		Profiles:         append([]string(nil), e.profileNames...),
		Active:           len(e.active),
		MaxActive:        e.maxActive,
		TotalLifetimeMS:  e.totalLifetime.Milliseconds(),
		SweepIntervalMS:  e.sweepInterval.Milliseconds(),
		OrphansReclaimed: e.orphansReclamed,
		Counters:         e.counters,
		LastError:        e.lastError,
		LastErrorUTC:     e.lastErrorUTC,
	}
	return status
}

// setLastError records a bounded last error without failing the caller.
func (e *Engine) setLastError(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.lastError = sanitizeText(err.Error())
	e.lastErrorUTC = e.clock().UTC()
	e.mu.Unlock()
}

// record appends best-effort engine evidence.
func (e *Engine) record(kind, detail, result string) {
	if e.ledger == nil {
		return
	}
	_ = e.ledger.Append(kind, sanitizeText(detail), result)
}
