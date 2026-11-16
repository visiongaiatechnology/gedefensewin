// STATUS: DIAMANT VGT SUPREME
//go:build windows

// Package parsercells isolates untrusted document parsers in ephemeral,
// kernel-enforced "parser cells" on Windows without a kernel driver.
//
// A cell is the product of four independent kernel primitives:
//
//   - an AppContainer profile (no network capability, no capabilities at all)
//   - a Job Object (single active process, job memory cap, per-process user
//     time cap, kill-on-job-close, die-on-unhandled-exception, all UI limits)
//   - a CreateProcess attribute block (AppContainer security capabilities,
//     Win32k system-call disable, font disable, dynamic-code prohibition,
//     Microsoft-signed-only image policy, image-load-no-remote, restricted
//     child-process policy and an explicit handle list)
//   - handle-based I/O only (one staged input handle and one anonymous output
//     pipe; the cell has no writable directory and no network).
//
// The package is Windows-only. Every implementation file carries a
// //go:build windows constraint; engine_other.go exists only so that a
// non-Windows build still resolves the package and fails closed with
// ErrUnsupportedPlatform instead of silently implying support.
//
// Isolation is only ever claimed after read-back. If a single property cannot
// be read back (job limits, AppContainer token SID, mitigation policies, input
// hash) the cell transitions to FAILED and never to ISOLATED.
package parsercells

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// State is the observable lifecycle state of one parser cell. The state machine
// is deliberately monotonic: isolation is only reachable in one direction and
// every failure path ends in FAILED, never back in ISOLATED.
type State string

const (
	// StateRequested is the initial state before any kernel object exists.
	StateRequested State = "REQUESTED"
	// StateSpawned means the process exists inside AppContainer and job, but the
	// full read-back has not completed yet.
	StateSpawned State = "SPAWNED"
	// StateIsolated means every isolation property was read back successfully
	// and the cell is executing.
	StateIsolated State = "ISOLATED"
	// StateExpiring means the runtime budget is exhausted or the parser finished;
	// the cell must be burned. It is never reachable by an unverified cell.
	StateExpiring State = "EXPIRING"
	// StateBurning means cleanup is in progress.
	StateBurning State = "BURNING"
	// StateBurned is terminal: job closed, profile deleted, staging removed.
	StateBurned State = "BURNED"
	// StateFailed is terminal for a run: at least one isolation property was not
	// verified or cleanup failed. A failed cell is never reported as isolated.
	StateFailed State = "FAILED"
)

// Terminal reports whether no further lifecycle transition is required.
func (s State) Terminal() bool {
	return s == StateBurned || s == StateFailed
}

// Valid reports whether s is a defined state.
func (s State) Valid() bool {
	switch s {
	case StateRequested, StateSpawned, StateIsolated, StateExpiring, StateBurning, StateBurned, StateFailed:
		return true
	default:
		return false
	}
}

// stateTransitions is the complete allow-list of the lifecycle state machine.
// FAILED is reachable from every non-terminal state (fail closed), BURNING is
// reachable from every non-terminal state (emergency abort) and BURNED only
// from BURNING. There is intentionally no path back to REQUESTED, SPAWNED or
// ISOLATED.
var stateTransitions = map[State][]State{
	StateRequested: {StateSpawned, StateBurning, StateFailed},
	StateSpawned:   {StateIsolated, StateExpiring, StateBurning, StateFailed},
	StateIsolated:  {StateExpiring, StateBurning, StateFailed},
	StateExpiring:  {StateBurning, StateFailed},
	StateBurning:   {StateBurned, StateFailed},
	StateBurned:    {},
	StateFailed:    {StateBurning, StateBurned},
}

// transitionAllowed reports whether from -> to is part of the state machine.
func transitionAllowed(from, to State) bool {
	for _, candidate := range stateTransitions[from] {
		if candidate == to {
			return true
		}
	}
	return false
}

// Error is a typed, bounded lifecycle or validation error. It never carries
// unbounded operating-system text: Detail is truncated by the constructors.
type Error struct {
	Op     string
	Kind   error
	Detail string
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Detail == "" {
		return fmt.Sprintf("%s: %v", e.Op, e.Kind)
	}
	return fmt.Sprintf("%s: %v: %s", e.Op, e.Kind, e.Detail)
}

// Unwrap exposes the sentinel error for errors.Is/errors.As.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Kind
}

// Sentinel errors. All failure paths use these; %w is used for details where a
// wrapped operating-system error adds diagnostic value.
var (
	// ErrUnsupportedPlatform is returned by the non-Windows stub.
	ErrUnsupportedPlatform = errors.New("parsercells: package is Windows-only")
	// ErrInvalidProfile rejects a profile that cannot be executed safely.
	ErrInvalidProfile = errors.New("parsercells: invalid profile")
	// ErrInvalidState rejects a lifecycle call in the wrong state.
	ErrInvalidState = errors.New("parsercells: invalid cell state")
	// ErrIsolationNotVerified is returned when a kernel property could not be
	// read back. The cell must not start in that case.
	ErrIsolationNotVerified = errors.New("parsercells: isolation property not verified")
	// ErrSaturated is returned by the engine when the bounded active-cell
	// capacity is exhausted.
	ErrSaturated = errors.New("parsercells: cell capacity exhausted")
	// ErrClosed is returned by the engine after Close.
	ErrClosed = errors.New("parsercells: engine closed")
	// ErrInputTooLarge rejects input above the profile or hard ceiling.
	ErrInputTooLarge = errors.New("parsercells: input exceeds profile limit")
	// ErrRuntimeExceeded reports that the parser hit its runtime budget; the
	// cell was frozen and must be burned.
	ErrRuntimeExceeded = errors.New("parsercells: runtime budget exhausted")
	// ErrContainerExists means an AppContainer profile with the requested name
	// already exists. Creating a cell never reuses a profile (fail closed).
	ErrContainerExists = errors.New("parsercells: appcontainer profile already exists")
	// ErrContainerNotFound is used for idempotent profile deletion.
	ErrContainerNotFound = errors.New("parsercells: appcontainer profile not found")
	// ErrStagingUnsafe rejects a staging path with traversal, reparse points or
	// an unexpected DACL.
	ErrStagingUnsafe = errors.New("parsercells: staging path unsafe")
)

// Hard ceilings. They are independent of the profile document so a malformed or
// hostile profile cannot raise them.
const (
	// HardMaxInputBytes is the absolute input ceiling (8 MiB).
	HardMaxInputBytes int64 = 8 << 20
	// HardMaxOutputBytes is the absolute output ceiling (2 MiB).
	HardMaxOutputBytes int64 = 2 << 20
	// HardMaxMemoryBytes is the absolute job memory ceiling (1 GiB).
	HardMaxMemoryBytes int64 = 1 << 30
	// HardMinMemoryBytes keeps a cell above the point where the parser would
	// fail for reasons unrelated to its input.
	HardMinMemoryBytes int64 = 16 << 20
	// HardMaxRuntime is the absolute lifetime of one parser run.
	HardMaxRuntime = 5 * time.Minute
	// HardMinRuntime is the shortest budget that still lets a parser start.
	HardMinRuntime = 100 * time.Millisecond
	// HardMaxProfiles bounds the number of profiles in one document.
	HardMaxProfiles = 64
	// MaxDocumentBytes bounds the profile document before parsing (64 KiB).
	MaxDocumentBytes = 64 << 10
	// MaxDetailBytes bounds every stored/ledger error detail.
	MaxDetailBytes = 1024
	// MaxEvidence is the maximum number of evidence strings per finding.
	MaxEvidence = 8
)

// Mitigation names used by Profile.RequiredMitigations and by the read-back
// verification. They map one-to-one to the process mitigations requested in
// sandbox_windows.go.
const (
	MitigationWin32kSystemCallDisable   = "win32k_system_call_disable"
	MitigationFontDisable               = "font_disable"
	MitigationProhibitDynamicCode       = "prohibit_dynamic_code"
	MitigationBlockNonMicrosoftBinaries = "block_non_microsoft_binaries"
	MitigationImageLoadNoRemote         = "image_load_no_remote"
	MitigationChildProcessRestricted    = "child_process_restricted"
)

// MandatoryMitigations returns the mitigations that every cell must have. The
// sandbox always requests all of them; the return value is a fresh slice so the
// caller cannot mutate shared state.
func MandatoryMitigations() []string {
	return []string{
		MitigationWin32kSystemCallDisable,
		MitigationFontDisable,
		MitigationProhibitDynamicCode,
		MitigationBlockNonMicrosoftBinaries,
		MitigationImageLoadNoRemote,
		MitigationChildProcessRestricted,
	}
}

// supportedMitigation reports whether name is a mitigation this package can
// request and read back.
func supportedMitigation(name string) bool {
	for _, known := range MandatoryMitigations() {
		if name == known {
			return true
		}
	}
	return false
}

// Profile is the immutable, validated resource envelope of one parser class.
// Values are enforced by the job object and by the cell runtime, not by the
// parser binary itself.
type Profile struct {
	// Name is the profile identifier from parser-profiles.conf.
	Name string
	// MaxInputBytes caps the staged input. Never above HardMaxInputBytes.
	MaxInputBytes int64
	// MaxOutputBytes caps the harvested output. Never above HardMaxOutputBytes.
	MaxOutputBytes int64
	// MaxRuntime caps wall-clock execution time. Never above HardMaxRuntime.
	MaxRuntime time.Duration
	// MaxMemoryBytes caps the job commit charge. Bounded by HardMaxMemoryBytes.
	MaxMemoryBytes int64
	// MaxProcesses is always 1: a parser cell is a single process.
	MaxProcesses int
	// NetworkAllowed must be false. An AppContainer cell is created with zero
	// capabilities, which is a kernel network lock.
	NetworkAllowed bool
	// RequiredMitigations must be a non-empty subset of MandatoryMitigations().
	RequiredMitigations []string
}

// DefaultProfile returns the safe defaults for a named profile. Every limit is
// small; a caller must opt in to larger limits explicitly through the validated
// document parser.
func DefaultProfile(name string) Profile {
	return Profile{
		Name:                name,
		MaxInputBytes:       1 << 20,
		MaxOutputBytes:      512 << 10,
		MaxRuntime:          2 * time.Second,
		MaxMemoryBytes:      128 << 20,
		MaxProcesses:        1,
		NetworkAllowed:      false,
		RequiredMitigations: MandatoryMitigations(),
	}
}

// Validate checks the profile against the hard ceilings. It is pure and uses no
// operating-system state. A zero value is not valid; callers use
// DefaultProfile and override fields.
func (p Profile) Validate() error {
	if err := validateProfileName(p.Name); err != nil {
		return err
	}
	if p.MaxInputBytes <= 0 || p.MaxInputBytes > HardMaxInputBytes {
		return &Error{Op: "profile.validate", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("max input %d outside (0,%d]", p.MaxInputBytes, HardMaxInputBytes)}
	}
	if p.MaxOutputBytes <= 0 || p.MaxOutputBytes > HardMaxOutputBytes {
		return &Error{Op: "profile.validate", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("max output %d outside (0,%d]", p.MaxOutputBytes, HardMaxOutputBytes)}
	}
	if p.MaxRuntime < HardMinRuntime || p.MaxRuntime > HardMaxRuntime {
		return &Error{Op: "profile.validate", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("max runtime %s outside [%s,%s]", p.MaxRuntime, HardMinRuntime, HardMaxRuntime)}
	}
	if p.MaxMemoryBytes < HardMinMemoryBytes || p.MaxMemoryBytes > HardMaxMemoryBytes {
		return &Error{Op: "profile.validate", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("max memory %d outside [%d,%d]", p.MaxMemoryBytes, HardMinMemoryBytes, HardMaxMemoryBytes)}
	}
	if p.MaxProcesses != 1 {
		return &Error{Op: "profile.validate", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("max processes %d: a parser cell is exactly one process", p.MaxProcesses)}
	}
	if p.NetworkAllowed {
		return &Error{Op: "profile.validate", Kind: ErrInvalidProfile,
			Detail: "network_allowed=true is forbidden: cells have zero capabilities"}
	}
	if len(p.RequiredMitigations) == 0 {
		return &Error{Op: "profile.validate", Kind: ErrInvalidProfile,
			Detail: "required_mitigations must not be empty"}
	}
	if len(p.RequiredMitigations) > len(MandatoryMitigations()) {
		return &Error{Op: "profile.validate", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("too many required mitigations: %d", len(p.RequiredMitigations))}
	}
	seen := make(map[string]struct{}, len(p.RequiredMitigations))
	for _, mitigation := range p.RequiredMitigations {
		if !supportedMitigation(mitigation) {
			return &Error{Op: "profile.validate", Kind: ErrInvalidProfile,
				Detail: fmt.Sprintf("unsupported mitigation %q", sanitizeText(mitigation))}
		}
		if _, duplicate := seen[mitigation]; duplicate {
			return &Error{Op: "profile.validate", Kind: ErrInvalidProfile,
				Detail: fmt.Sprintf("duplicate mitigation %q", mitigation)}
		}
		seen[mitigation] = struct{}{}
	}
	return nil
}

// validateProfileName enforces a bounded identifier: lowercase ASCII letters,
// digits and dashes, 1..32 characters, no path separator and no leading dash.
func validateProfileName(name string) error {
	if len(name) == 0 || len(name) > 32 {
		return &Error{Op: "profile.name", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("name length %d outside [1,32]", len(name))}
	}
	for index := 0; index < len(name); index++ {
		value := name[index]
		switch {
		case value >= 'a' && value <= 'z':
		case value >= '0' && value <= '9':
		case value == '-':
			if index == 0 || index == len(name)-1 {
				return &Error{Op: "profile.name", Kind: ErrInvalidProfile,
					Detail: "name must not start or end with a dash"}
			}
		default:
			return &Error{Op: "profile.name", Kind: ErrInvalidProfile,
				Detail: fmt.Sprintf("invalid character 0x%02x in profile name", value)}
		}
	}
	return nil
}

// CellStatus is the bounded, read-only snapshot of one cell. It never exposes
// kernel handles.
type CellStatus struct {
	ID              string    `json:"id"`
	ProfileName     string    `json:"profileName"`
	State           State     `json:"state"`
	Reason          string    `json:"reason,omitempty"`
	InputSHA256     string    `json:"inputSha256,omitempty"`
	ContainerSID    string    `json:"containerSid,omitempty"`
	PID             uint32    `json:"pid,omitempty"`
	ExitCode        uint32    `json:"exitCode"`
	CreatedUTC      time.Time `json:"createdUtc"`
	UpdatedUTC      time.Time `json:"updatedUtc"`
	InputBytes      int64     `json:"inputBytes"`
	OutputBytes     int64     `json:"outputBytes"`
	OutputTruncated bool      `json:"outputTruncated"`
	RuntimeMS       int64     `json:"runtimeMs"`
	Freezes         uint32    `json:"freezes"`
	Burns           uint32    `json:"burns"`
	Verifications   uint32    `json:"verifications"`
	VerifyFailures  uint32    `json:"verifyFailures"`
	// VerifiedMitigations lists the mitigation properties read back from the
	// live process. Empty until StateIsolated is attempted.
	VerifiedMitigations []string `json:"verifiedMitigations,omitempty"`
}

// Result is the bounded outcome of one parser run. Output is copied from a
// capped buffer and is never larger than the profile output ceiling.
type Result struct {
	CellID              string
	State               State
	Output              []byte
	OutputTruncated     bool
	ExitCode            uint32
	InputSHA256         string
	ContainerSID        string
	PID                 uint32
	Runtime             time.Duration
	VerifiedMitigations []string
}

// Severity mirrors the product severity scale so parser-cell findings can flow
// into the existing evidence path.
type Severity string

const (
	// SeverityInfo is informational evidence.
	SeverityInfo Severity = "INFO"
	// SeverityMedium is a degraded but safe condition.
	SeverityMedium Severity = "MEDIUM"
	// SeverityHigh is an isolation property failure.
	SeverityHigh Severity = "HIGH"
	// SeverityCritical is a fail-closed refusal to run untrusted input.
	SeverityCritical Severity = "CRITICAL"
)

// Finding is one bounded, evidence-carrying observation of the parser-cell
// subsystem. It never claims more than was actually read back.
type Finding struct {
	ObservedUTC time.Time `json:"observedUtc"`
	Kind        string    `json:"kind"`
	Severity    Severity  `json:"severity"`
	CellID      string    `json:"cellId,omitempty"`
	Detail      string    `json:"detail"`
	Evidence    []string  `json:"evidence,omitempty"`
}

// Ledger is the evidence sink. It mirrors the existing project style (a small
// append interface) so the engine cannot depend on the concrete ledger
// implementation and stays testable. A nil ledger is valid.
type Ledger interface {
	Append(kind, detail, result string) error
}

// sanitizeText bounds and normalizes text that originates from the operating
// system or from caller input before it is stored, logged or returned.
func sanitizeText(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
	if len(value) > MaxDetailBytes {
		value = value[:MaxDetailBytes]
	}
	return value
}

// boundedEvidence copies at most MaxEvidence non-empty, bounded entries.
func boundedEvidence(values ...string) []string {
	result := make([]string, 0, MaxEvidence)
	for _, value := range values {
		if len(result) >= MaxEvidence {
			break
		}
		value = sanitizeText(value)
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result
}

// newCellID returns a lowercase RFC 4122 version 4 UUID generated from
// crypto/rand. It is the only source of cell identity and profile names.
func newCellID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("parsercells: cell id entropy: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], raw[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], raw[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], raw[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], raw[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], raw[10:16])
	return string(encoded), nil
}

// validCellID reports whether id has the exact canonical UUID v4 shape used by
// profile names. It is deliberately stricter than a general UUID parser.
func validCellID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for index := 0; index < len(id); index++ {
		value := id[index]
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value != '-' {
				return false
			}
			continue
		}
		switch {
		case value >= '0' && value <= '9':
		case value >= 'a' && value <= 'f':
		default:
			return false
		}
	}
	return id[14] == '4' && (id[19] == '8' || id[19] == '9' || id[19] == 'a' || id[19] == 'b')
}

// runtimeBudget returns the effective wall-clock budget: the tighter of the
// profile budget and the caller deadline.
func runtimeBudget(ctxDeadline time.Time, now time.Time, budget time.Duration) (time.Duration, bool) {
	if budget <= 0 || budget > HardMaxRuntime {
		return 0, false
	}
	if !ctxDeadline.IsZero() {
		remaining := ctxDeadline.Sub(now)
		if remaining <= 0 {
			return 0, false
		}
		if remaining < budget {
			return remaining, true
		}
	}
	return budget, true
}
