// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	// PollingSchemaVersion is the on-disk schema of the operator polling policy.
	PollingSchemaVersion = 1
	// MinPollInterval prevents an operator from hammering external feeds or
	// creating an unintentionally aggressive synchronization loop.
	MinPollInterval = 15 * time.Minute
	// MaxPollInterval bounds feed staleness for an automatically polled source.
	MaxPollInterval = 7 * 24 * time.Hour
	// DefaultPollInterval preserves the historical twelve-hour cadence.
	DefaultPollInterval = SyncInterval
	// maximumPollingStateBytes bounds the persisted operator policy file so a
	// corrupted or hostile file cannot force unbounded parsing work.
	maximumPollingStateBytes = 4 << 10
)

const (
	pollingSourceDefault   = "DEFAULT"
	pollingSourcePersisted = "PERSISTED"
	pollingSourceInvalid   = "INVALID_DEFAULT"
)

// PollingConfig is the validated, persisted automatic synchronization policy
// together with the derived scheduling state the UI renders.
type PollingConfig struct {
	IntervalSeconds        int       `json:"intervalSeconds"`
	DefaultIntervalSeconds int       `json:"defaultIntervalSeconds"`
	MinIntervalSeconds     int       `json:"minIntervalSeconds"`
	MaxIntervalSeconds     int       `json:"maxIntervalSeconds"`
	Source                 string    `json:"source"`
	UpdatedUTC             time.Time `json:"updatedUtc,omitempty"`
	LastAttemptUTC         time.Time `json:"lastAttemptUtc"`
	LastSyncUTC            time.Time `json:"lastSuccessUtc"`
	NextPollUTC            time.Time `json:"nextPollUtc"`
	Error                  string    `json:"error,omitempty"`
}

type pollingState struct {
	SchemaVersion   int       `json:"schemaVersion"`
	IntervalSeconds int       `json:"intervalSeconds"`
	UpdatedUTC      time.Time `json:"updatedUtc"`
}

func pollingConfigPath(root string) string {
	return filepath.Join(root, "polling.json")
}

func pollIntervalRange() (minimum, maximum int) {
	return int(MinPollInterval / time.Second), int(MaxPollInterval / time.Second)
}

func validatePollIntervalSeconds(seconds int) error {
	minimum, maximum := pollIntervalRange()
	if seconds < minimum || seconds > maximum {
		return fmt.Errorf("threat intelligence polling interval %d seconds outside [%d,%d]", seconds, minimum, maximum)
	}
	return nil
}

// loadPollingConfig restores the persisted polling policy. Invalid or
// out-of-range files are never partially trusted: the default cadence remains
// active and the rejection is surfaced through PollingConfig.Error.
func (m *Manager) loadPollingConfig() {
	raw, err := os.ReadFile(pollingConfigPath(m.root))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	reject := func() {
		m.pollMu.Lock()
		m.pollSource = pollingSourceInvalid
		m.pollLoadError = "persisted polling interval rejected; default cadence active"
		m.pollMu.Unlock()
	}
	if err != nil || len(raw) == 0 || len(raw) > maximumPollingStateBytes {
		reject()
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state pollingState
	if err := decoder.Decode(&state); err != nil {
		reject()
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		reject()
		return
	}
	if state.SchemaVersion != PollingSchemaVersion || validatePollIntervalSeconds(state.IntervalSeconds) != nil {
		reject()
		return
	}
	m.pollMu.Lock()
	m.pollEvery = time.Duration(state.IntervalSeconds) * time.Second
	m.pollSource = pollingSourcePersisted
	m.pollUpdatedUTC = state.UpdatedUTC
	m.pollLoadError = ""
	m.pollMu.Unlock()
}

func (m *Manager) pollInterval() time.Duration {
	m.pollMu.RLock()
	defer m.pollMu.RUnlock()
	if m.pollEvery <= 0 {
		return DefaultPollInterval
	}
	return m.pollEvery
}

// pollingFields returns the additive Status projection of the polling policy.
func (m *Manager) pollingFields() (intervalSeconds int, source string, updatedUTC time.Time, loadError string) {
	m.pollMu.RLock()
	defer m.pollMu.RUnlock()
	source = m.pollSource
	if source == "" {
		source = pollingSourceDefault
	}
	return int(m.pollInterval() / time.Second), source, m.pollUpdatedUTC, m.pollLoadError
}

// PollingConfig returns the effective polling policy, its validation envelope
// and the derived last/next synchronization timestamps.
func (m *Manager) PollingConfig() PollingConfig {
	minimum, maximum := pollIntervalRange()
	if m == nil {
		return PollingConfig{
			IntervalSeconds:        int(DefaultPollInterval / time.Second),
			DefaultIntervalSeconds: int(DefaultPollInterval / time.Second),
			MinIntervalSeconds:     minimum,
			MaxIntervalSeconds:     maximum,
			Source:                 pollingSourceDefault,
		}
	}
	status := m.Status()
	_, _, _, pollingLoadError := m.pollingFields()
	polling := PollingConfig{
		IntervalSeconds:        status.PollingIntervalSeconds,
		DefaultIntervalSeconds: int(DefaultPollInterval / time.Second),
		MinIntervalSeconds:     minimum,
		MaxIntervalSeconds:     maximum,
		Source:                 status.PollingIntervalSource,
		UpdatedUTC:             status.PollingUpdatedUTC,
		LastAttemptUTC:         status.LastAttemptUTC,
		LastSyncUTC:            status.LastSuccessUTC,
		NextPollUTC:            status.NextSyncUTC,
		Error:                  pollingLoadError,
	}
	return polling
}

// SetPollingIntervalSeconds validates, atomically persists and activates a new
// automatic polling interval. The previous interval remains effective when
// validation or persistence fails. Feed authority, safety gates and the
// failure retry cadence are untouched.
func (m *Manager) SetPollingIntervalSeconds(seconds int) (PollingConfig, error) {
	if m == nil {
		return PollingConfig{}, errors.New("threat intelligence manager unavailable")
	}
	if err := validatePollIntervalSeconds(seconds); err != nil {
		return m.PollingConfig(), err
	}
	m.pollSetMu.Lock()
	defer m.pollSetMu.Unlock()

	updatedUTC := time.Now().UTC()
	payload, err := json.Marshal(pollingState{SchemaVersion: PollingSchemaVersion, IntervalSeconds: seconds, UpdatedUTC: updatedUTC})
	if err != nil {
		return m.PollingConfig(), err
	}
	if err := atomicWrite(pollingConfigPath(m.root), append(payload, '\n')); err != nil {
		return m.PollingConfig(), fmt.Errorf("threat intelligence polling persistence: %w", err)
	}

	m.pollMu.Lock()
	m.pollEvery = time.Duration(seconds) * time.Second
	m.pollSource = pollingSourcePersisted
	m.pollUpdatedUTC = updatedUTC
	m.pollLoadError = ""
	m.pollMu.Unlock()

	// Recompute the next automatic poll from the observed schedule so a newly
	// shortened interval takes effect immediately instead of after the old
	// twelve-hour timer.
	m.statusMu.Lock()
	if m.status.NextSyncUTC.IsZero() {
		// No completed attempt yet: the next loop iteration is immediately due.
		m.status.NextSyncUTC = time.Time{}
	} else if !m.status.LastAttemptUTC.IsZero() {
		m.status.NextSyncUTC = m.status.LastAttemptUTC.Add(time.Duration(seconds) * time.Second)
	} else if !m.status.LastSuccessUTC.IsZero() {
		m.status.NextSyncUTC = m.status.LastSuccessUTC.Add(time.Duration(seconds) * time.Second)
	}
	m.statusMu.Unlock()
	return m.PollingConfig(), nil
}
