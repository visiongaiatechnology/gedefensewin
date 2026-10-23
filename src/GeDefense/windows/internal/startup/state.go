// STATUS: PLATIN
package startup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	reasonFirstRun       = "first-run"
	reasonVersionChanged = "version-changed"
	reasonReboot         = "reboot"
	reasonNone           = ""
)

// Result is the server-authoritative answer to "must the readiness dialog be
// shown on this UI open?" The UI must not invent this decision from local
// browser state: a reinstall, an update or a real Windows reboot invalidates a
// previously completed check.
type Result struct {
	Required        bool      `json:"required"`
	Reason          string    `json:"reason"`
	Version         string    `json:"version"`
	CurrentVersion  string    `json:"currentVersion"`
	LastVersion     string    `json:"lastVersion,omitempty"`
	LastBootUTC     time.Time `json:"lastBootUtc,omitempty"`
	AcknowledgedUTC time.Time `json:"acknowledgedUtc,omitempty"`
	SinceUTC        time.Time `json:"sinceUtc,omitempty"`
}

type persisted struct {
	Version         string    `json:"version"`
	UptimeMS        uint64    `json:"uptimeMs"`
	AcknowledgedUTC time.Time `json:"acknowledgedUtc"`
	// SetupCompletedUTC is written only after the first-run wizard verified the
	// active protection posture. It is deliberately separate from readiness: a
	// reboot asks for readiness again, but must not force the first-run wizard.
	SetupCompletedUTC time.Time `json:"setupCompletedUtc,omitempty"`
	SetupProfile      string    `json:"setupProfile,omitempty"`
}

// SetupResult is the server-authoritative answer to "does this installation
// still need its first-run setup?".
type SetupResult struct {
	Complete       bool      `json:"complete"`
	Profile        string    `json:"profile,omitempty"`
	CompletedUTC   time.Time `json:"completedUtc,omitempty"`
	CurrentVersion string    `json:"currentVersion"`
}

type State struct {
	mu   sync.Mutex
	path string
}

func Open(path string) (*State, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("startup state path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &State{path: path}, nil
}

func (s *State) Required(version string) (Result, error) {
	if version == "" {
		return Result{}, errors.New("startup version is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	current := readUptime()
	previous, err := s.loadLocked()
	base := Result{Version: version, CurrentVersion: version}
	if errors.Is(err, os.ErrNotExist) {
		base.Required, base.Reason = true, reasonFirstRun
		return base, nil
	}
	if err != nil {
		// A damaged marker must fail toward running the check, never toward
		// silently claiming the host was already verified.
		base.Required, base.Reason = true, "state-unreadable"
		return base, nil
	}
	base.LastVersion = previous.Version
	base.AcknowledgedUTC = previous.AcknowledgedUTC
	base.SinceUTC = previous.AcknowledgedUTC
	if previous.UptimeMS > 0 && previous.UptimeMS < uint64((100*365*24*time.Hour)/time.Millisecond) {
		base.LastBootUTC = time.Now().UTC().Add(-time.Duration(previous.UptimeMS) * time.Millisecond)
	}
	if previous.Version != version {
		base.Required, base.Reason = true, reasonVersionChanged
		return base, nil
	}
	// GetTickCount64 resets at boot. A materially smaller current uptime is
	// therefore a reboot even if the version and the marker are unchanged.
	if current+5000 < previous.UptimeMS {
		base.Required, base.Reason = true, reasonReboot
		return base, nil
	}
	base.Required, base.Reason = false, reasonNone
	return base, nil
}

// Acknowledge is called only after the full readiness check has completed and
// the user has seen the result. The marker is written atomically.
func (s *State) Acknowledge(version string) (Result, error) {
	if version == "" {
		return Result{}, errors.New("startup version is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	previous, loadErr := s.loadLocked()
	setupProfile := ""
	var setupCompleted time.Time
	if loadErr == nil {
		setupProfile = previous.SetupProfile
		setupCompleted = previous.SetupCompletedUTC
	}
	payload, err := json.Marshal(persisted{
		Version: version, UptimeMS: readUptime(), AcknowledgedUTC: now,
		SetupProfile: setupProfile, SetupCompletedUTC: setupCompleted,
	})
	if err != nil {
		return Result{}, err
	}
	payload = append(payload, '\n')
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".startup-state-*.tmp")
	if err != nil {
		return Result{}, err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return Result{}, err
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return Result{}, err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return Result{}, err
	}
	if err := temp.Close(); err != nil {
		return Result{}, err
	}
	if err := os.Rename(tempName, s.path); err != nil {
		return Result{}, fmt.Errorf("startup state commit: %w", err)
	}
	return Result{Required: false, Reason: reasonNone, Version: version, CurrentVersion: version, AcknowledgedUTC: now, SinceUTC: now, LastBootUTC: time.Now().UTC().Add(-time.Duration(readUptime()) * time.Millisecond)}, nil
}

func (s *State) SetupStatus(version string) (SetupResult, error) {
	if version == "" {
		return SetupResult{}, errors.New("setup version is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, err := s.loadLocked()
	if errors.Is(err, os.ErrNotExist) {
		return SetupResult{Complete: false, CurrentVersion: version}, nil
	}
	if err != nil {
		return SetupResult{}, err
	}
	return SetupResult{
		Complete:       !previous.SetupCompletedUTC.IsZero(),
		Profile:        previous.SetupProfile,
		CompletedUTC:   previous.SetupCompletedUTC,
		CurrentVersion: version,
	}, nil
}

// CompleteSetup records the first-run choice only after the caller has verified
// that real protection is active. The readiness marker is preserved.
func (s *State) CompleteSetup(profile, version string) (SetupResult, error) {
	if version == "" {
		return SetupResult{}, errors.New("setup version is required")
	}
	switch profile {
	case "personal", "business", "server", "developer":
	default:
		return SetupResult{}, errors.New("setup profile is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	previous, loadErr := s.loadLocked()
	if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		return SetupResult{}, loadErr
	}
	if errors.Is(loadErr, os.ErrNotExist) {
		previous = persisted{Version: version, AcknowledgedUTC: now}
	}
	previous.Version = version
	previous.UptimeMS = readUptime()
	previous.SetupCompletedUTC = now
	previous.SetupProfile = profile
	payload, err := json.Marshal(previous)
	if err != nil {
		return SetupResult{}, err
	}
	payload = append(payload, '\n')
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".startup-state-*.tmp")
	if err != nil {
		return SetupResult{}, err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return SetupResult{}, err
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return SetupResult{}, err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return SetupResult{}, err
	}
	if err := temp.Close(); err != nil {
		return SetupResult{}, err
	}
	if err := os.Rename(tempName, s.path); err != nil {
		return SetupResult{}, fmt.Errorf("setup state commit: %w", err)
	}
	return SetupResult{Complete: true, Profile: profile, CompletedUTC: now, CurrentVersion: version}, nil
}

func (s *State) loadLocked() (persisted, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return persisted{}, err
	}
	var value persisted
	if err := json.Unmarshal(raw, &value); err != nil {
		return persisted{}, err
	}
	if value.Version == "" || value.AcknowledgedUTC.IsZero() {
		return persisted{}, errors.New("startup state is incomplete")
	}
	return value, nil
}
