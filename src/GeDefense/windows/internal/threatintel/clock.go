// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

const (
	feedClockSchemaVersion = 1
	feedClockTolerance     = 5 * time.Minute
	feedClockFileName      = "clock-high-water.json"
)

type feedClockState struct {
	SchemaVersion int       `json:"schemaVersion"`
	HighWaterUTC  time.Time `json:"highWaterUtc"`
}

func feedClockPath(root string) string {
	return root + string(os.PathSeparator) + feedClockFileName
}

// loadFeedClock restores the wall-clock high-water mark persisted by the last
// successful synchronization.
func loadFeedClock(root string) (time.Time, error) {
	raw, err := os.ReadFile(feedClockPath(root))
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	if len(raw) == 0 || len(raw) > 4<<10 {
		return time.Time{}, errors.New("feed clock state size rejected")
	}
	var state feedClockState
	if err := json.Unmarshal(raw, &state); err != nil || state.SchemaVersion != feedClockSchemaVersion {
		return time.Time{}, errors.New("feed clock state rejected")
	}
	return state.HighWaterUTC, nil
}

func (m *Manager) persistFeedClock(now time.Time) {
	state := feedClockState{SchemaVersion: feedClockSchemaVersion, HighWaterUTC: now.UTC()}
	raw, err := json.Marshal(state)
	if err != nil {
		return
	}
	_ = atomicWrite(feedClockPath(m.root), append(raw, '\n'))
}

// observeClock records the supplied wall-clock time as the trusted high-water
// mark. It reports whether a backwards jump was detected.
func (m *Manager) observeClock(now time.Time) bool {
	m.clockMu.Lock()
	defer m.clockMu.Unlock()
	if m.clockHighWater.IsZero() {
		m.clockHighWater = now
		return false
	}
	if now.Add(feedClockTolerance).Before(m.clockHighWater) {
		m.clockRollback = true
		return true
	}
	if now.After(m.clockHighWater) {
		m.clockHighWater = now
	}
	return m.clockRollback
}

// effectiveNowUTC never returns a timestamp before the trusted high-water mark:
// after a rollback, freshness/TTL calculations still advance (fail-closed)
// instead of making old data look young again (DP-FIND-014).
func (m *Manager) effectiveNowUTC() time.Time {
	now := time.Now().UTC()
	m.clockMu.RLock()
	defer m.clockMu.RUnlock()
	if m.clockHighWater.After(now) {
		return m.clockHighWater
	}
	return now
}

func (m *Manager) clockRollbackDetected() bool {
	m.clockMu.RLock()
	defer m.clockMu.RUnlock()
	return m.clockRollback
}

// maxFeedAge is the hard freshness TTL. It is derived from the operator polling
// interval (two intervals) but never shorter than one historical sync interval
// and never longer than 48 hours.
func (m *Manager) maxFeedAge() time.Duration {
	age := 2 * m.pollInterval()
	if age < SyncInterval {
		age = SyncInterval
	}
	if age > 48*time.Hour {
		age = 48 * time.Hour
	}
	return age
}
