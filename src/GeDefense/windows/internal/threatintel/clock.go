// STATUS: PLATIN VGT SUPREME
package threatintel

// FIND-WIN-015: authenticated wall-clock high-water state (DP-FIND-014 follow up).
//
// The feed freshness/TTL logic trusts the local wall clock. The persisted
// high-water mark is what detects a backwards clock jump, so an unauthenticated
// clock-high-water.json is a denial-of-service primitive: an actor who can write
// the intelligence data root could stamp a far-future date, which then makes
// every feed look expired (freshness withdrawn) or, after a clock reset, makes
// stale data look young again. The file is therefore:
//
//   - authenticated with a service-local HMAC key derived from the
//     secretfs-protected feed policy key (file DACL via secretfs, constant-time
//     comparison), and
//   - bounded against implausible future dates: a value beyond the documented
//     tolerance is never adopted as the effective "now".
//
// Failure semantics: a missing file is the documented first-run/bootstrap state.
// A present but invalid file is never trusted, sets an evident clock error and
// fails closed (blocking enforcement withdrawn) until the operator removes or
// repairs it. A record with a valid MAC but an implausible future date is treated
// as rollback/tamper evidence and is not adopted either.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence/secretfs"
)

const (
	// feedClockSchemaVersion 2 is the authenticated format. Version 1 (unauthenticated)
	// files are rejected, never silently rewritten by the loader.
	feedClockSchemaVersion = 2
	feedClockTolerance     = 5 * time.Minute
	// feedClockMaximumFutureSkew bounds how far ahead of the local clock an
	// authenticated high-water value may claim to be before it is treated as an
	// implausible/tampered value instead of a genuine (small) clock rollback.
	feedClockMaximumFutureSkew = 24 * time.Hour
	feedClockFileName          = "clock-high-water.json"
	feedClockMACDomain         = "VGT-GEDEFENSE-FEED-CLOCK-MAC-V1"
	maxFeedClockFileBytes      = 4 << 10
)

// feedClockState is the on-disk authenticated high-water record.
type feedClockState struct {
	SchemaVersion int       `json:"schemaVersion"`
	HighWaterUTC  time.Time `json:"highWaterUtc"`
	MAC           string    `json:"mac"`
}

// feedClockMACPayload is the canonical MAC input.
type feedClockMACPayload struct {
	SchemaVersion int    `json:"schemaVersion"`
	HighWaterUTC  string `json:"highWaterUtc"`
}

func feedClockPath(root string) string {
	return filepath.Join(root, feedClockFileName)
}

// feedClockMACKey derives a dedicated MAC key from the secretfs-protected feed
// policy key. Domain separation keeps the clock MAC independent from the feed
// override store MAC even though both use the same protected root key.
func feedClockMACKey(rawKey []byte) []byte {
	derived := hmac.New(sha256.New, rawKey)
	_, _ = derived.Write([]byte(feedClockMACDomain))
	return derived.Sum(nil)
}

func feedClockMAC(key []byte, payload feedClockMACPayload) (string, error) {
	if len(key) != sha256.Size {
		return "", errors.New("feed clock key rejected")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func feedClockPayload(highWater time.Time) feedClockMACPayload {
	return feedClockMACPayload{SchemaVersion: feedClockSchemaVersion, HighWaterUTC: highWater.UTC().Format(time.RFC3339Nano)}
}

// loadFeedClock restores and authenticates the persisted wall-clock high-water
// mark. A missing file is a first-run state (zero time, no error). Every present
// but unusable file returns an error; the caller then treats the clock as
// untrusted instead of adopting a possibly forged date.
func loadFeedClock(root string, key []byte) (time.Time, error) {
	path := feedClockPath(root)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("feed clock state unreadable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return time.Time{}, errors.New("feed clock state must be a regular non-reparse file")
	}
	if info.Size() <= 0 || info.Size() > maxFeedClockFileBytes {
		return time.Time{}, errors.New("feed clock state size rejected")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("feed clock state unreadable: %w", err)
	}
	var state feedClockState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return time.Time{}, errors.New("feed clock state rejected")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return time.Time{}, errors.New("feed clock state trailing data rejected")
	}
	if state.SchemaVersion != feedClockSchemaVersion || state.HighWaterUTC.IsZero() || len(state.MAC) != 64 {
		return time.Time{}, errors.New("feed clock state metadata rejected")
	}
	expected, err := feedClockMAC(key, feedClockPayload(state.HighWaterUTC))
	if err != nil {
		return time.Time{}, err
	}
	if !signatureHMACEqual(expected, state.MAC) {
		return time.Time{}, errors.New("feed clock state authentication failed")
	}
	return state.HighWaterUTC.UTC(), nil
}

// writeFeedClockState atomically persists an authenticated high-water mark and
// applies the secretfs file DACL. Shared by the sync path and regression tests.
func writeFeedClockState(root string, key []byte, highWater time.Time) error {
	if highWater.IsZero() {
		return errors.New("feed clock high-water timestamp rejected")
	}
	mac, err := feedClockMAC(key, feedClockPayload(highWater))
	if err != nil {
		return err
	}
	raw, err := json.Marshal(feedClockState{SchemaVersion: feedClockSchemaVersion, HighWaterUTC: highWater.UTC(), MAC: mac})
	if err != nil {
		return err
	}
	if len(raw)+1 > maxFeedClockFileBytes {
		return errors.New("feed clock state exceeds the file boundary")
	}
	path := feedClockPath(root)
	if err := atomicWrite(path, append(raw, '\n')); err != nil {
		return err
	}
	if _, err := secretfs.HardenFile(path); err != nil {
		return fmt.Errorf("feed clock state access control: %w", err)
	}
	return nil
}

// persistFeedClock records the supplied wall-clock time as the authenticated
// high-water mark. The caller must surface failures: a failed persistence only
// degrades rollback detection, it never makes a future date trusted.
func (m *Manager) persistFeedClock(now time.Time) error {
	if len(m.clockKey) != sha256.Size {
		return errors.New("feed clock key unavailable")
	}
	return writeFeedClockState(m.root, m.clockKey, now)
}

// observeClock records the supplied wall-clock time as the trusted high-water
// mark. It reports whether a backwards jump (or an untrusted clock state) must
// stop synchronization.
func (m *Manager) observeClock(now time.Time) bool {
	m.clockMu.Lock()
	defer m.clockMu.Unlock()
	if m.clockStateError != "" || m.clockRollback {
		m.clockRollback = true
		return true
	}
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
// instead of making old data look young again (DP-FIND-014). Only a plausibly
// authenticated high-water value is ever stored, so this can never return an
// implausible forged future date.
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

// clockErrorText returns the bounded, operator-visible clock trust problem.
func (m *Manager) clockErrorText() string {
	m.clockMu.RLock()
	defer m.clockMu.RUnlock()
	return m.clockStateError
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
