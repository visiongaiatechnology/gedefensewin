// STATUS: PLATIN VGT SUPREME

package lockdown

// Reversible key-broker freeze (port of rust/gedefense-core/src/lockdown_brokers.rs).
//
// The freezer only ever suspends and resumes the fixed broker name list through
// an injected ProcessController. Every action is bound to the recorded identity
// pair (PID + process creation time): a recycled PID is refused by the
// controller and is never signalled. Freeze/Resume are the ntdll
// NtSuspendProcess/NtResumeProcess calls of the production adapter.
//
// Protection boundaries are hard: PID<=4, the engine's own process and the
// critical Windows names (lsass.exe, csrss.exe, ...) are never touched. The scan
// is bounded to 512 processes and to 256 remembered identities.
//
// The honest status is frozen-not-locked: a reversible freeze, not a zeroized key
// store. Records older than the 300 s TTL are not resumed (bounded action window,
// documented limitation); failed resumes stay recorded so a retried clear can
// release them.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// BrokerMaxFrozen bounds the remembered identities.
	BrokerMaxFrozen = 256
	// BrokerMaxScan bounds one process scan.
	BrokerMaxScan = 512
	// BrokerFreezeTTL bounds the age of an identity that is still resumed.
	BrokerFreezeTTL = 300 * time.Second
	// BrokerStatusFrozenNotLocked is the honest status of a broker phase.
	BrokerStatusFrozenNotLocked = "frozen-not-locked"
)

// brokerNames is the fixed broker/remote-desktop process set. No
// operator-supplied names and no path matching.
var brokerNames = [...]string{
	"ssh-agent.exe", "gpg-agent.exe", "keepassxc.exe", "1password.exe",
	"bitwarden.exe", "vault.exe", "mstsc.exe", "rdpclip.exe",
}

// protectedProcessNames are never frozen, even if they ever matched a broker
// name. lsass.exe is the documented hard boundary; the others are the critical
// Windows session/system processes.
var protectedProcessNames = [...]string{
	"lsass.exe", "csrss.exe", "wininit.exe", "services.exe",
	"smss.exe", "winlogon.exe", "system", "idle", "registry",
	"memory compression", "svchost.exe",
}

// ProcessInfo is one process inventory entry with its identity pair.
type ProcessInfo struct {
	PID              uint32
	Name             string
	CreationUnixNano int64
}

// ProcessController is the injected process interface. The production adapter is
// the ntdll NtSuspendProcess/NtResumeProcess implementation; tests inject a fake.
type ProcessController interface {
	// ListProcesses returns a bounded process inventory with creation times.
	ListProcesses(ctx context.Context) ([]ProcessInfo, error)
	// Suspend stops the process. The controller must verify that the creation
	// time still matches the recorded identity before signalling.
	Suspend(pid uint32, creationUnixNano int64) error
	// Resume continues the process under the same identity check.
	Resume(pid uint32, creationUnixNano int64) error
}

// FrozenBroker is one remembered identity.
type FrozenBroker struct {
	PID              uint32
	Name             string
	CreationUnixNano int64
	FrozenAt         time.Time
}

// BrokerReport is the bounded outcome of one broker freeze/resume.
type BrokerReport struct {
	Status    string
	Scanned   int
	Frozen    int
	Resumed   int
	Failed    int
	Expired   int
	Protected int
	Bounded   bool
	Detail    string
}

// BrokerFreezer remembers which identities were stopped. It is safe for
// concurrent use and owns no goroutine.
type BrokerFreezer struct {
	mu     sync.Mutex
	ownPID uint32
	frozen []FrozenBroker
}

// NewBrokerFreezer returns an empty freezer bound to the calling process.
func NewBrokerFreezer() *BrokerFreezer {
	return &BrokerFreezer{ownPID: uint32(os.Getpid())}
}

// FrozenCount returns the number of remembered identities.
func (f *BrokerFreezer) FrozenCount() int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.frozen)
}

// Frozen returns a copy of the remembered identities.
func (f *BrokerFreezer) Frozen() []FrozenBroker {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FrozenBroker(nil), f.frozen...)
}

// isBrokerName reports the case-insensitive fixed-name match.
func isBrokerName(name string) bool {
	for _, candidate := range brokerNames {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}

// isProtectedProcessName reports the critical-name boundary.
func isProtectedProcessName(name string) bool {
	for _, candidate := range protectedProcessNames {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}

// Freeze stops every named broker that is not stopped yet and records the
// identity pair. It is idempotent per identity.
func (f *BrokerFreezer) Freeze(ctx context.Context, controller ProcessController, now time.Time) (BrokerReport, error) {
	report := BrokerReport{Status: "no-brokers"}
	if f == nil {
		return report, fmt.Errorf("%w: no freezer is attached", ErrProcessControllerUnavailable)
	}
	if controller == nil {
		return report, ErrProcessControllerUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	processes, err := controller.ListProcesses(ctx)
	if err != nil {
		report.Status = "scan-failed"
		report.Detail = truncateText("process inventory failed: "+err.Error(), MaxDetailBytes)
		return report, fmt.Errorf("broker process scan failed: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	examined := 0
	for _, process := range processes {
		if err := ctx.Err(); err != nil {
			report.Detail = appendDetail(report.Detail, "interrupted: "+err.Error())
			return report, fmt.Errorf("broker freeze interrupted: %w", err)
		}
		if examined >= BrokerMaxScan {
			report.Bounded = true
			break
		}
		examined++
		name := strings.TrimSpace(process.Name)
		if !isBrokerName(name) {
			continue
		}
		if process.PID <= 4 || process.PID == f.ownPID || isProtectedProcessName(name) {
			report.Protected++
			continue
		}
		if process.CreationUnixNano <= 0 {
			// Without the creation time there is no safe identity: never suspend.
			report.Failed++
			report.Detail = appendDetail(report.Detail, "identity unavailable for pid "+formatPID(process.PID))
			continue
		}
		if f.alreadyFrozenLocked(process.PID, process.CreationUnixNano) {
			continue
		}
		if len(f.frozen) >= BrokerMaxFrozen {
			report.Bounded = true
			break
		}
		if err := controller.Suspend(process.PID, process.CreationUnixNano); err != nil {
			report.Failed++
			report.Detail = appendDetail(report.Detail, "suspend refused: "+err.Error())
			continue
		}
		f.frozen = append(f.frozen, FrozenBroker{
			PID: process.PID, Name: name,
			CreationUnixNano: process.CreationUnixNano, FrozenAt: now,
		})
		report.Frozen++
	}
	report.Scanned = examined
	switch {
	case report.Frozen > 0 && report.Failed > 0:
		report.Status = "partial"
	case report.Frozen > 0:
		report.Status = BrokerStatusFrozenNotLocked
		report.Detail = appendDetail(report.Detail, "a reversible process freeze, not a zeroized key store")
	case report.Failed > 0:
		report.Status = "failed"
	default:
		report.Status = "no-brokers"
	}
	if report.Bounded {
		report.Detail = appendDetail(report.Detail, "scan bounded")
	}
	return report, nil
}

// Resume continues the remembered identities that are still inside the TTL.
// Failed resumes stay recorded so a retried clear can release them; expired
// identities are dropped without a signal (documented limitation).
func (f *BrokerFreezer) Resume(ctx context.Context, controller ProcessController, now time.Time) (BrokerReport, error) {
	report := BrokerReport{Status: "no-brokers"}
	if f == nil {
		return report, fmt.Errorf("%w: no freezer is attached", ErrProcessControllerUnavailable)
	}
	if controller == nil {
		return report, ErrProcessControllerUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	records := f.frozen
	remaining := make([]FrozenBroker, 0, len(records))
	report.Scanned = len(records)
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			remaining = append(remaining, record)
			report.Detail = appendDetail(report.Detail, "interrupted: "+err.Error())
			f.frozen = remaining
			return report, fmt.Errorf("broker resume interrupted: %w", err)
		}
		if now.Sub(record.FrozenAt) > BrokerFreezeTTL {
			report.Expired++
			continue
		}
		if err := controller.Resume(record.PID, record.CreationUnixNano); err != nil {
			report.Failed++
			report.Detail = appendDetail(report.Detail, "resume refused: "+err.Error())
			remaining = append(remaining, record)
			continue
		}
		report.Resumed++
	}
	f.frozen = remaining
	switch {
	case report.Failed > 0:
		report.Status = "resume-failed"
	case report.Resumed > 0:
		report.Status = "resumed"
	case report.Expired > 0:
		report.Status = "identity-ttl-expired"
		report.Detail = appendDetail(report.Detail, "frozen identities exceeded the 300s TTL and were not resumed")
	default:
		report.Status = "no-brokers"
	}
	return report, nil
}

// alreadyFrozenLocked reports the idempotent identity match.
func (f *BrokerFreezer) alreadyFrozenLocked(pid uint32, creationUnixNano int64) bool {
	for _, record := range f.frozen {
		if record.PID == pid && record.CreationUnixNano == creationUnixNano {
			return true
		}
	}
	return false
}

// formatPID renders a bounded PID token.
func formatPID(pid uint32) string {
	return fmt.Sprintf("%d", pid)
}

// BrokersPhase is the BROKERS engine phase.
type BrokersPhase struct {
	Controller ProcessController
	Freezer    *BrokerFreezer
	Clock      Clock
	timeout    time.Duration
}

// NewBrokersPhase returns the BROKERS phase. A nil controller yields the honest
// NOT_IMPLEMENTED result; tests and production inject the ntdll adapter.
func NewBrokersPhase(controller ProcessController, clock Clock) *BrokersPhase {
	return &BrokersPhase{Controller: controller, Freezer: NewBrokerFreezer(), Clock: clock, timeout: DefaultPhaseTimeout}
}

func (p *BrokersPhase) Name() PhaseName        { return PhaseBrokers }
func (p *BrokersPhase) Timeout() time.Duration { return p.timeout }

// Engage freezes the fixed broker set and reports what the controller
// acknowledged.
func (p *BrokersPhase) Engage(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseBrokers}
	if p.Controller == nil || p.Freezer == nil {
		result.Status = PhaseUnavailable
		result.Detail = "NOT_IMPLEMENTED: no Windows process controller is attached; broker freeze requires the ntdll suspend/resume adapter"
		return result
	}
	report, err := p.Freezer.Freeze(ctx, p.Controller, nowFrom(p.Clock))
	if err != nil {
		result.Status = PhaseFailed
		result.Detail = truncateText("broker freeze failed: "+err.Error(), MaxDetailBytes)
		return result
	}
	result.Targets = report.Frozen
	detail := report.Detail
	if report.Frozen > 0 {
		detail = appendDetail(fmt.Sprintf("%s: %d broker process(es) suspended by pid+creation-time identity", BrokerStatusFrozenNotLocked, report.Frozen), detail)
	}
	if report.Protected > 0 {
		detail = appendDetail(detail, fmt.Sprintf("%d protected process(es) were skipped", report.Protected))
	}
	switch {
	case report.Failed > 0 && report.Frozen > 0:
		result.Status = PhasePartial
	case report.Failed > 0:
		result.Status = PhaseFailed
	default:
		result.Status = PhaseApplied
		if report.Frozen == 0 {
			detail = appendDetail(detail, "no broker process is present")
		}
	}
	result.Detail = truncateText(detail, MaxDetailBytes)
	return result
}

// Release resumes the remembered identities.
func (p *BrokersPhase) Release(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseBrokers}
	if p.Controller == nil || p.Freezer == nil {
		result.Status = PhaseApplied
		result.Detail = "nothing to release: no broker freezer is attached"
		return result
	}
	report, err := p.Freezer.Resume(ctx, p.Controller, nowFrom(p.Clock))
	if err != nil {
		result.Status = PhaseFailed
		result.Detail = truncateText("broker resume failed: "+err.Error(), MaxDetailBytes)
		return result
	}
	result.Targets = report.Resumed
	detail := report.Detail
	switch {
	case report.Failed > 0:
		// A failed resume is never reported as released.
		result.Status = PhaseFailed
		if detail == "" {
			detail = "frozen broker identities could not be resumed"
		}
	case report.Expired > 0 && report.Resumed == 0:
		result.Status = PhasePartial
		detail = appendDetail(detail, "review the expired frozen identities manually")
	case report.Resumed > 0:
		result.Status = PhaseApplied
		detail = appendDetail(detail, fmt.Sprintf("%d broker process(es) resumed under their recorded identity", report.Resumed))
	default:
		result.Status = PhaseApplied
		detail = appendDetail(detail, "no frozen broker identity remained")
	}
	result.Detail = truncateText(detail, MaxDetailBytes)
	return result
}

// Verify reports that Windows exposes no documented per-process suspension
// read-back. The phase result stays applied but explicitly unverified.
func (p *BrokersPhase) Verify(context.Context) error {
	return fmt.Errorf("%w: process suspension state has no documented Windows read-back", ErrVerificationUnavailable)
}
