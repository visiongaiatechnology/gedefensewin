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
	payload, err := json.Marshal(persisted{Version: version, UptimeMS: readUptime(), AcknowledgedUTC: now})
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
