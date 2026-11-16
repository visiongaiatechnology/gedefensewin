// STATUS: DIAMANT VGT SUPREME
//go:build windows

package parsercells

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// platform is the injectable set of kernel adapters used by a cell. The
// production implementation is windowsPlatform (appcontainer_windows.go,
// jobobject_windows.go, sandbox_windows.go, staging_windows.go,
// pipe_windows.go); tests substitute fakes and never touch the kernel.
type platform interface {
	CreateContainer(name string) (container, error)
	DeriveContainerSID(name string) (string, error)
	DeleteContainer(name string) error
	NewJob(limits jobLimits) (job, error)
	PrepareRoot() error
	StageInput(cellID, profileName string, data []byte, containerSID string) (stagedInput, error)
	VerifyStagedInput(staged stagedInput) error
	PurgeStaging(staged stagedInput) error
	OpenInputHandle(path string) (syscall.Handle, error)
	CreateOutputPipe() (syscall.Handle, syscall.Handle, error)
	DrainOutput(handle syscall.Handle, limit int64, timeout time.Duration) ([]byte, bool, error)
	Launch(spec launchSpec) (launchedProcess, error)
	VerifyContainerToken(process syscall.Handle, expectedSID string) error
	VerifyMitigations(process syscall.Handle) ([]string, error)
	ResumeThread(thread syscall.Handle) error
	SuspendProcess(process syscall.Handle) error
	WaitProcess(process syscall.Handle, timeout time.Duration) (uint32, bool, error)
	WriteOrphan(record orphanRecord) error
	ClearOrphan(cellID string) error
	ScanOrphans(limit int) ([]orphanRecord, error)
	ReclaimOrphan(ctx context.Context, record orphanRecord) error
}

// CellOptions configures one ephemeral parser cell.
type CellOptions struct {
	// ID is the cell UUID. Empty means a fresh crypto/rand UUID v4 is generated.
	ID string
	// Root is the absolute, canonical staging root.
	Root string
	// Ledger optionally records lifecycle evidence.
	Ledger Ledger
	// Clock is injectable for tests. Defaults to time.Now.
	Clock func() time.Time
	// platform is injectable for tests. Defaults to the Windows adapters.
	platform platform
}

// drainResult is the bounded output harvest result.
type drainResult struct {
	data      []byte
	truncated bool
	err       error
}

// waitResult is the process wait result.
type waitResult struct {
	exitCode uint32
	timedOut bool
	err      error
}

// Cell is one ephemeral parser cell. All lifecycle methods are safe for
// concurrent use; destructive operations are serialized through the state
// machine and through the spawn barrier so a burn can never race a spawn.
type Cell struct {
	mu sync.Mutex

	id       string
	root     string
	clock    func() time.Time
	ledger   Ledger
	platform platform

	profile    Profile
	state      State
	reason     string
	createdUTC time.Time
	updatedUTC time.Time
	spawnDone  chan struct{}

	container        container
	containerCreated bool
	job              job
	process          syscall.Handle
	thread           syscall.Handle
	pid              uint32
	staged           stagedInput
	stagedPresent    bool
	journaled        bool

	exitCode        uint32
	output          []byte
	outputTruncated bool
	runtime         time.Duration
	inputSHA256     string
	mitigations     []string

	freezes        uint32
	burns          uint32
	verifications  uint32
	verifyFailures uint32
}

// NewCell validates the static options and returns a cell in REQUESTED state.
func NewCell(options CellOptions) (*Cell, error) {
	if options.Root == "" {
		return nil, &Error{Op: "cell.new", Kind: ErrInvalidProfile, Detail: "staging root is required"}
	}
	if err := ValidateStagingRoot(options.Root); err != nil {
		return nil, &Error{Op: "cell.new", Kind: ErrStagingUnsafe, Detail: err.Error()}
	}
	cellID := options.ID
	if cellID == "" {
		generated, err := newCellID()
		if err != nil {
			return nil, err
		}
		cellID = generated
	} else if !validCellID(cellID) {
		return nil, &Error{Op: "cell.new", Kind: ErrInvalidState, Detail: "cell id is not a canonical UUID v4"}
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	adapter := options.platform
	if adapter == nil {
		adapter = newPlatform(options.Root)
	}
	now := clock().UTC()
	return &Cell{
		id:         cellID,
		root:       options.Root,
		clock:      clock,
		ledger:     options.Ledger,
		platform:   adapter,
		state:      StateRequested,
		createdUTC: now,
		updatedUTC: now,
	}, nil
}

// ID returns the immutable cell UUID.
func (c *Cell) ID() string { return c.id }

// Status returns a bounded, read-only snapshot.
func (c *Cell) Status() CellStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	status := CellStatus{
		ID:                  c.id,
		ProfileName:         c.profile.Name,
		State:               c.state,
		Reason:              c.reason,
		InputSHA256:         c.inputSHA256,
		ContainerSID:        c.container.SID,
		PID:                 c.pid,
		ExitCode:            c.exitCode,
		CreatedUTC:          c.createdUTC,
		UpdatedUTC:          c.updatedUTC,
		InputBytes:          c.staged.Bytes,
		OutputBytes:         int64(len(c.output)),
		OutputTruncated:     c.outputTruncated,
		RuntimeMS:           c.runtime.Milliseconds(),
		Freezes:             c.freezes,
		Burns:               c.burns,
		Verifications:       c.verifications,
		VerifyFailures:      c.verifyFailures,
		VerifiedMitigations: append([]string(nil), c.mitigations...),
	}
	return status
}

// Create stages the input, spawns the parser inside AppContainer + Job Object,
// verifies every isolation property by read-back and then executes the parser
// with a bounded runtime and a bounded output pipe. Create returns only after
// the parser finished or was stopped; the caller must call Burn afterwards.
func (c *Cell) Create(ctx context.Context, profile Profile, input []byte, executable string) (Result, error) {
	var zero Result
	if err := profile.Validate(); err != nil {
		return zero, err
	}
	if int64(len(input)) > profile.MaxInputBytes {
		return zero, &Error{Op: "cell.create", Kind: ErrInputTooLarge,
			Detail: fmt.Sprintf("input %d bytes exceeds profile limit %d", len(input), profile.MaxInputBytes)}
	}
	if err := validateExecutable(executable); err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("parsercells: create canceled: %w", err)
	}
	containerName, err := newContainerName(c.id)
	if err != nil {
		return zero, err
	}

	c.mu.Lock()
	if c.state != StateRequested {
		state := c.state
		c.mu.Unlock()
		return zero, &Error{Op: "cell.create", Kind: ErrInvalidState, Detail: "cell is in state " + string(state)}
	}
	c.profile = profile
	c.spawnDone = make(chan struct{})
	c.mu.Unlock()

	result, err := c.createLocked(ctx, containerName, input, executable)
	c.endSpawn()
	if err != nil {
		c.fail(err)
		return result, err
	}
	return result, nil
}

// createLocked runs the spawn pipeline. On error the kernel objects stay owned by
// the cell so Burn can reclaim them; no partial object is silently forgotten.
func (c *Cell) createLocked(ctx context.Context, containerName string, input []byte, executable string) (Result, error) {
	now := c.clock().UTC()
	if err := c.platform.WriteOrphan(orphanRecord{CellID: c.id, ContainerName: containerName, CreatedUTC: now}); err != nil {
		return Result{}, fmt.Errorf("parsercells: journal cell intent: %w", err)
	}
	c.mu.Lock()
	c.journaled = true
	c.mu.Unlock()

	createdContainer, err := c.platform.CreateContainer(containerName)
	if err != nil {
		return Result{}, fmt.Errorf("parsercells: create appcontainer: %w", err)
	}
	c.mu.Lock()
	c.container = createdContainer
	c.containerCreated = true
	c.mu.Unlock()

	staged, err := c.platform.StageInput(c.id, c.profile.Name, input, createdContainer.SID)
	if err != nil {
		return Result{}, fmt.Errorf("parsercells: stage input: %w", err)
	}
	c.mu.Lock()
	c.staged = staged
	c.stagedPresent = true
	c.inputSHA256 = staged.SHA256
	c.mu.Unlock()
	if err := c.platform.VerifyStagedInput(staged); err != nil {
		return Result{}, err
	}

	limits := jobLimitsForProfile(c.profile)
	createdJob, err := c.platform.NewJob(limits)
	if err != nil {
		return Result{}, fmt.Errorf("parsercells: create job: %w", err)
	}
	c.mu.Lock()
	c.job = createdJob
	c.mu.Unlock()

	inputHandle, err := c.platform.OpenInputHandle(staged.Path)
	if err != nil {
		return Result{}, err
	}
	readHandle, writeHandle, err := c.platform.CreateOutputPipe()
	if err != nil {
		_ = closeHandle(inputHandle)
		return Result{}, err
	}
	// Both parent-side handles are closed no matter how the launch ends.
	defer func() { _ = closeHandle(readHandle) }()

	launched, launchErr := c.platform.Launch(launchSpec{
		Executable:   executable,
		ContainerSID: createdContainer.SID,
		Input:        inputHandle,
		Output:       writeHandle,
	})
	_ = closeHandle(inputHandle)
	_ = closeHandle(writeHandle)
	if launchErr != nil {
		return Result{}, fmt.Errorf("parsercells: launch sandboxed process: %w", launchErr)
	}

	c.mu.Lock()
	c.process = launched.Process
	c.thread = launched.Thread
	c.pid = launched.PID
	if err := c.transitionLocked(StateSpawned); err != nil {
		c.mu.Unlock()
		return Result{}, err
	}
	c.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("parsercells: canceled after spawn: %w", err)
	}

	// Assign the suspended process to the job, then prove membership.
	if err := c.platformAssignAndVerify(limits); err != nil {
		return Result{}, err
	}
	if err := c.platform.VerifyContainerToken(launched.Process, createdContainer.SID); err != nil {
		return Result{}, err
	}
	mitigations, err := c.platform.VerifyMitigations(launched.Process)
	if err != nil {
		return Result{}, err
	}
	if err := c.platform.ResumeThread(launched.Thread); err != nil {
		return Result{}, err
	}
	c.mu.Lock()
	c.thread = 0
	c.mitigations = append([]string(nil), mitigations...)
	if err := c.transitionLocked(StateIsolated); err != nil {
		c.mu.Unlock()
		return Result{}, err
	}
	c.mu.Unlock()
	c.record("parser-cell.isolated", "cell "+c.id+" verified and running", "ISOLATED")
	c.endSpawn()

	return c.execute(ctx, readHandle)
}

// platformAssignAndVerify assigns the process to the job and reads every job
// property back.
func (c *Cell) platformAssignAndVerify(limits jobLimits) error {
	c.mu.Lock()
	createdJob := c.job
	process := c.process
	pid := c.pid
	c.mu.Unlock()
	if createdJob == nil || process == 0 {
		return &Error{Op: "cell.assign", Kind: ErrIsolationNotVerified, Detail: "job or process missing"}
	}
	if err := createdJob.Assign(process); err != nil {
		return err
	}
	assigned, err := createdJob.IsProcessAssigned(process)
	if err != nil {
		return err
	}
	if !assigned {
		return &Error{Op: "cell.assign", Kind: ErrIsolationNotVerified, Detail: "process is not in the cell job"}
	}
	readback, err := createdJob.Readback()
	if err != nil {
		return err
	}
	if err := limits.Verify(readback); err != nil {
		return err
	}
	pids, err := createdJob.MemberPIDs(1)
	if err != nil {
		return err
	}
	if len(pids) != 1 || pids[0] != pid {
		return &Error{Op: "cell.assign", Kind: ErrIsolationNotVerified,
			Detail: fmt.Sprintf("job member list does not match the spawned process (members=%d)", len(pids))}
	}
	return nil
}

// execute drains output while waiting for the bounded run to finish.
func (c *Cell) execute(ctx context.Context, readHandle syscall.Handle) (Result, error) {
	c.mu.Lock()
	process := c.process
	profile := c.profile
	deadline := c.createdUTC.Add(profile.MaxRuntime)
	c.mu.Unlock()
	budget, ok := runtimeBudget(deadline, c.clock().UTC(), profile.MaxRuntime)
	if !ok {
		return Result{}, &Error{Op: "cell.execute", Kind: ErrRuntimeExceeded, Detail: "runtime budget already exhausted"}
	}

	drainChannel := make(chan drainResult, 1)
	go func() {
		data, truncated, err := c.platform.DrainOutput(readHandle, profile.MaxOutputBytes, profile.MaxRuntime+5*time.Second)
		drainChannel <- drainResult{data: data, truncated: truncated, err: err}
	}()

	waitChannel := make(chan waitResult, 1)
	go func() {
		exitCode, timedOut, err := c.platform.WaitProcess(process, budget)
		waitChannel <- waitResult{exitCode: exitCode, timedOut: timedOut, err: err}
	}()

	var waited waitResult
	var waitErr error
	select {
	case waited = <-waitChannel:
	case <-ctx.Done():
		waitErr = fmt.Errorf("parsercells: run canceled: %w", ctx.Err())
		c.terminateJob()
		waited = awaitWait(waitChannel, 5*time.Second)
	}
	if waitErr == nil && waited.err != nil {
		waitErr = fmt.Errorf("parsercells: wait for parser: %w", waited.err)
	}
	if waitErr == nil && waited.timedOut {
		waitErr = ErrRuntimeExceeded
	}
	if waitErr != nil {
		c.terminateJob()
	}
	drained := awaitDrain(drainChannel, readHandle, 10*time.Second)

	c.mu.Lock()
	c.exitCode = waited.exitCode
	c.runtime = c.clock().UTC().Sub(c.createdUTC)
	if drained.data != nil {
		c.output = drained.data
	}
	c.outputTruncated = drained.truncated
	stateErr := c.transitionLocked(StateExpiring)
	if stateErr != nil {
		c.mu.Unlock()
		return Result{}, stateErr
	}
	result := Result{
		CellID:              c.id,
		State:               StateExpiring,
		Output:              c.output,
		OutputTruncated:     c.outputTruncated,
		ExitCode:            c.exitCode,
		InputSHA256:         c.inputSHA256,
		ContainerSID:        c.container.SID,
		PID:                 c.pid,
		Runtime:             c.runtime,
		VerifiedMitigations: append([]string(nil), c.mitigations...),
	}
	c.mu.Unlock()

	switch {
	case waitErr != nil:
		c.record("parser-cell.expiring", "cell "+c.id+" stopped: "+sanitizeText(waitErr.Error()), "EXPIRING")
		return result, waitErr
	case drained.err != nil:
		c.record("parser-cell.output", "cell "+c.id+" output harvest incomplete: "+sanitizeText(drained.err.Error()), "EXPIRING")
		return result, fmt.Errorf("parsercells: output harvest: %w", drained.err)
	default:
		c.record("parser-cell.expiring", "cell "+c.id+" completed", "EXPIRING")
		return result, nil
	}
}

// Freeze suspends the parser through NtSuspendProcess. Only an isolated cell can
// be frozen; freezing never changes the isolation state.
func (c *Cell) Freeze(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("parsercells: freeze canceled: %w", err)
	}
	c.mu.Lock()
	if c.state != StateIsolated {
		state := c.state
		c.mu.Unlock()
		return &Error{Op: "cell.freeze", Kind: ErrInvalidState, Detail: "freeze requires ISOLATED, state is " + string(state)}
	}
	process := c.process
	if c.freezes < ^uint32(0) {
		c.freezes++
	}
	c.mu.Unlock()
	if process == 0 {
		return &Error{Op: "cell.freeze", Kind: ErrInvalidState, Detail: "process handle is already released"}
	}
	if err := c.platform.SuspendProcess(process); err != nil {
		return err
	}
	c.record("parser-cell.freeze", "cell "+c.id+" frozen", "FROZEN")
	return nil
}

// Verify re-reads every isolation property of a live cell. A verification
// failure moves the cell to FAILED; the caller must burn it.
func (c *Cell) Verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("parsercells: verify canceled: %w", err)
	}
	c.mu.Lock()
	if c.state != StateIsolated && c.state != StateExpiring {
		state := c.state
		c.mu.Unlock()
		return &Error{Op: "cell.verify", Kind: ErrInvalidState, Detail: "verify requires ISOLATED or EXPIRING, state is " + string(state)}
	}
	createdJob := c.job
	process := c.process
	staged := c.staged
	containerSID := c.container.SID
	pid := c.pid
	limits := jobLimitsForProfile(c.profile)
	if c.verifications < ^uint32(0) {
		c.verifications++
	}
	c.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("parsercells: verify canceled: %w", err)
	}
	verifyErr := c.verifyLive(createdJob, process, pid, staged, containerSID, limits)
	c.mu.Lock()
	if verifyErr != nil {
		if c.verifyFailures < ^uint32(0) {
			c.verifyFailures++
		}
		c.mu.Unlock()
		c.fail(verifyErr)
		return verifyErr
	}
	c.mu.Unlock()
	c.record("parser-cell.verified", "cell "+c.id+" isolation re-verified", "ISOLATED")
	return nil
}

// verifyLive performs the read-back checks shared by Verify.
func (c *Cell) verifyLive(createdJob job, process syscall.Handle, pid uint32, staged stagedInput, containerSID string, limits jobLimits) error {
	if createdJob == nil || process == 0 {
		return &Error{Op: "cell.verify.live", Kind: ErrIsolationNotVerified, Detail: "job or process handle is released"}
	}
	assigned, err := createdJob.IsProcessAssigned(process)
	if err != nil {
		return err
	}
	if !assigned {
		return &Error{Op: "cell.verify.live", Kind: ErrIsolationNotVerified, Detail: "process left the cell job"}
	}
	readback, err := createdJob.Readback()
	if err != nil {
		return err
	}
	if err := limits.Verify(readback); err != nil {
		return err
	}
	pids, err := createdJob.MemberPIDs(1)
	if err != nil {
		return err
	}
	if len(pids) != 1 || pids[0] != pid {
		return &Error{Op: "cell.verify.live", Kind: ErrIsolationNotVerified, Detail: "job member list changed"}
	}
	if err := c.platform.VerifyStagedInput(staged); err != nil {
		return err
	}
	if err := c.platform.VerifyContainerToken(process, containerSID); err != nil {
		return err
	}
	mitigations, err := c.platform.VerifyMitigations(process)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.mitigations = append([]string(nil), mitigations...)
	c.mu.Unlock()
	return nil
}

// Burn is the idempotent cleanup: terminate the job, close every handle, delete
// the AppContainer profile, purge staging and clear the crash journal. A failed
// cleanup leaves the cell in FAILED so a second Burn retries; a successful or
// already completed Burn returns nil.
func (c *Cell) Burn(ctx context.Context) error {
	c.mu.Lock()
	if c.state == StateBurned {
		c.mu.Unlock()
		return nil
	}
	if c.spawnDone != nil {
		barrier := c.spawnDone
		c.mu.Unlock()
		select {
		case <-barrier:
		case <-ctx.Done():
			return fmt.Errorf("parsercells: burn canceled while waiting for spawn: %w", ctx.Err())
		}
		c.mu.Lock()
	}
	if c.state != StateBurning {
		if err := c.transitionLocked(StateBurning); err != nil {
			state := c.state
			c.mu.Unlock()
			return &Error{Op: "cell.burn", Kind: ErrInvalidState, Detail: "burn from state " + string(state)}
		}
	}
	if c.burns < ^uint32(0) {
		c.burns++
	}
	createdJob := c.job
	c.job = nil
	process := c.process
	c.process = 0
	thread := c.thread
	c.thread = 0
	staged := c.staged
	stagedPresent := c.stagedPresent
	c.stagedPresent = false
	containerName := c.container.Name
	containerCreated := c.containerCreated
	c.containerCreated = false
	journaled := c.journaled
	c.journaled = false
	c.mu.Unlock()

	c.record("parser-cell.burn.intent", "burning cell "+c.id, "BURNING")

	var cleanupErrors []error
	if createdJob != nil {
		if err := createdJob.Terminate(0); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
		if err := createdJob.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if err := closeHandle(process); err != nil {
		cleanupErrors = append(cleanupErrors, err)
	}
	if err := closeHandle(thread); err != nil {
		cleanupErrors = append(cleanupErrors, err)
	}
	if containerCreated && containerName != "" {
		if err := c.platform.DeleteContainer(containerName); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if stagedPresent && staged.Dir != "" {
		if err := c.platform.PurgeStaging(staged); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if journaled {
		if err := c.platform.ClearOrphan(c.id); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}

	c.mu.Lock()
	cleanupErr := errors.Join(cleanupErrors...)
	if cleanupErr != nil {
		if transitionAllowed(c.state, StateFailed) {
			c.state = StateFailed
		}
		c.reason = sanitizeText("burn incomplete: " + cleanupErr.Error())
	} else {
		if c.state != StateBurned {
			c.state = StateBurned
		}
		c.reason = ""
	}
	c.updatedUTC = c.clock().UTC()
	c.mu.Unlock()

	if cleanupErr != nil {
		c.record("parser-cell.burn.result", "burn incomplete for cell "+c.id+": "+sanitizeText(cleanupErr.Error()), "FAILED")
		return cleanupErr
	}
	c.record("parser-cell.burn.result", "burned cell "+c.id, "BURNED")
	return nil
}

// terminateJob is a best-effort emergency stop used by the runtime watchdog.
func (c *Cell) terminateJob() {
	c.mu.Lock()
	createdJob := c.job
	c.mu.Unlock()
	if createdJob != nil {
		_ = createdJob.Terminate(0)
	}
}

// endSpawn releases the spawn barrier so a waiting Burn can proceed.
func (c *Cell) endSpawn() {
	c.mu.Lock()
	if c.spawnDone != nil {
		close(c.spawnDone)
		c.spawnDone = nil
	}
	c.mu.Unlock()
}

// fail records a FAILED state with a bounded reason unless the cell is already
// terminal or burning.
func (c *Cell) fail(err error) {
	c.mu.Lock()
	if c.state == StateBurned || c.state == StateBurning || c.state == StateFailed {
		c.mu.Unlock()
		return
	}
	if transitionAllowed(c.state, StateFailed) {
		c.state = StateFailed
	}
	c.reason = sanitizeText(err.Error())
	c.updatedUTC = c.clock().UTC()
	c.mu.Unlock()
	c.record("parser-cell.failed", "cell "+c.id+" failed closed: "+sanitizeText(err.Error()), "FAILED")
}

// transitionLocked applies a state transition; the caller holds c.mu.
func (c *Cell) transitionLocked(to State) error {
	if !transitionAllowed(c.state, to) {
		return &Error{Op: "cell.transition", Kind: ErrInvalidState,
			Detail: string(c.state) + " -> " + string(to) + " is forbidden"}
	}
	c.state = to
	c.updatedUTC = c.clock().UTC()
	return nil
}

// record appends best-effort evidence. A ledger failure never changes the
// isolation outcome and is ignored (the engine counts its own ledger evidence).
func (c *Cell) record(kind, detail, result string) {
	if c.ledger == nil {
		return
	}
	_ = c.ledger.Append(kind, sanitizeText(detail), result)
}

// awaitWait waits bounded for a process wait result after a forced stop.
func awaitWait(channel <-chan waitResult, timeout time.Duration) waitResult {
	select {
	case result := <-channel:
		return result
	case <-time.After(timeout):
		return waitResult{err: errors.New("parsercells: process wait did not settle after forced stop")}
	}
}

// awaitDrain waits bounded for the output drainer. On expiry the read handle is
// closed to abort the drainer and a timeout error is reported honestly.
func awaitDrain(channel <-chan drainResult, readHandle syscall.Handle, timeout time.Duration) drainResult {
	select {
	case result := <-channel:
		_ = closeHandle(readHandle)
		return result
	case <-time.After(timeout):
		_ = closeHandle(readHandle)
		select {
		case result := <-channel:
			if result.err == nil {
				result.err = errDrainTimeout
			}
			return result
		case <-time.After(2 * time.Second):
			return drainResult{err: errDrainTimeout}
		}
	}
}

// validateExecutable checks that the parser image is an absolute, canonical,
// regular .exe file and not a reparse point. It bounds the path and the file
// size before the kernel maps the image.
func validateExecutable(executable string) error {
	if executable == "" || len(executable) > maxStagingPathChars {
		return &Error{Op: "cell.executable", Kind: ErrInvalidProfile, Detail: "executable path is empty or too long"}
	}
	if strings.ContainsRune(executable, 0) {
		return &Error{Op: "cell.executable", Kind: ErrInvalidProfile, Detail: "executable path contains a NUL byte"}
	}
	if !filepath.IsAbs(executable) {
		return &Error{Op: "cell.executable", Kind: ErrInvalidProfile, Detail: "executable path must be absolute"}
	}
	if strings.HasPrefix(executable, `\\`) || strings.HasPrefix(executable, `//`) {
		return &Error{Op: "cell.executable", Kind: ErrInvalidProfile, Detail: "UNC and device namespaces are rejected"}
	}
	if !strings.HasSuffix(strings.ToLower(executable), ".exe") {
		return &Error{Op: "cell.executable", Kind: ErrInvalidProfile, Detail: "executable must be a .exe file"}
	}
	info, err := os.Lstat(executable)
	if err != nil {
		return fmt.Errorf("parsercells: executable stat: %w", err)
	}
	if !info.Mode().IsRegular() {
		return &Error{Op: "cell.executable", Kind: ErrInvalidProfile, Detail: "executable is not a regular file"}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return &Error{Op: "cell.executable", Kind: ErrInvalidProfile, Detail: "executable is a reparse point"}
	}
	if info.Size() <= 0 || info.Size() > 1<<30 {
		return &Error{Op: "cell.executable", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("executable size %d outside (0,%d]", info.Size(), int64(1)<<30)}
	}
	return nil
}
