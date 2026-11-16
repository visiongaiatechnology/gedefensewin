// STATUS: PLATIN VGT SUPREME
package threatintel

// FIND-WIN-015 regression tests for the authenticated wall-clock high-water
// anchor. The previous format was unauthenticated; an actor able to write the
// intelligence data root could stamp a future date and turn clock trust into a
// denial-of-service primitive.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence/secretfs"
)

// clockKeyForTest loads (or creates) the secretfs-protected key the manager
// derives the clock MAC key from.
func clockKeyForTest(t *testing.T, root string) []byte {
	t.Helper()
	rawKey, err := secretfs.LoadOrCreateRawKey(filepath.Join(root, "keys", "feed-policy.key"), 32)
	if err != nil {
		t.Fatalf("load feed policy key: %v", err)
	}
	return feedClockMACKey(rawKey)
}

func writeTestClockState(t *testing.T, root string, highWater time.Time) {
	t.Helper()
	if err := writeFeedClockState(root, clockKeyForTest(t, root), highWater); err != nil {
		t.Fatalf("write authenticated clock state: %v", err)
	}
}

func TestClockStateIsAuthenticatedAndLoaded(t *testing.T) {
	root := t.TempDir()
	highWater := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	writeTestClockState(t, root, highWater)
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	status := manager.Status()
	if status.FeedClockRollback || status.FeedClockError != "" {
		t.Fatalf("authenticated past clock mark misreported: %+v", status)
	}
	if manager.clockHighWater.IsZero() || !manager.clockHighWater.Equal(highWater) {
		t.Fatalf("authenticated clock mark not adopted: %v", manager.clockHighWater)
	}
	raw, err := os.ReadFile(feedClockPath(root))
	if err != nil || !strings.Contains(string(raw), `"mac"`) {
		t.Fatalf("clock state is not authenticated on disk: %v %s", err, raw)
	}
}

// A tampered/unauthenticated clock file is never trusted, no future date becomes
// effective "now", and the state fails closed with an evident error.
func TestClockStateInvalidAuthenticationFailsClosed(t *testing.T) {
	root := t.TempDir()
	if err := atomicWrite(feedClockPath(root), []byte(`{"schemaVersion":1,"highWaterUtc":"`+
		time.Now().UTC().Add(48*time.Hour).Format(time.RFC3339Nano)+`"}`+"\n")); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("broken clock state bricked the manager: %v", err)
	}
	status := manager.Status()
	if !status.FeedClockRollback {
		t.Fatalf("tampered clock state did not fail closed: %+v", status)
	}
	if status.FeedClockError == "" || !strings.Contains(strings.ToLower(status.FeedClockError), "rejected") {
		t.Fatalf("tampered clock state is not evident in status: %+v", status)
	}
	if manager.effectiveNowUTC().After(time.Now().UTC().Add(time.Minute)) {
		t.Fatalf("forged future clock date became the effective now: %v", manager.effectiveNowUTC())
	}
	if err := manager.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "wall-clock rollback") {
		t.Fatalf("sync did not refuse to run on an untrusted clock state: %v", err)
	}
}

// A correctly MACed but implausible far-future mark is not adopted as truth; it
// still fails closed instead of creating a permanent future "now".
func TestClockStateImplausibleFutureIsNotAdopted(t *testing.T) {
	root := t.TempDir()
	writeTestClockState(t, root, time.Now().UTC().Add(72*time.Hour))
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	status := manager.Status()
	if !status.FeedClockRollback {
		t.Fatalf("implausible future clock mark did not fail closed: %+v", status)
	}
	if status.FeedClockError == "" || !strings.Contains(status.FeedClockError, "implausibly") {
		t.Fatalf("implausible future clock mark is not evident: %+v", status)
	}
	if manager.effectiveNowUTC().After(time.Now().UTC().Add(time.Minute)) {
		t.Fatalf("implausible future clock mark was adopted as now: %v", manager.effectiveNowUTC())
	}
	if !manager.clockHighWater.IsZero() {
		t.Fatalf("implausible future clock mark was stored as trusted high-water: %v", manager.clockHighWater)
	}
}

// A plausible authenticated future mark means the clock moved backwards after the
// mark was written: rollback is detected and freshness advances monotonically.
func TestClockStateBackwardsJumpIsDetected(t *testing.T) {
	root := t.TempDir()
	highWater := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	writeTestClockState(t, root, highWater)
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	status := manager.Status()
	if !status.FeedClockRollback || status.FeedClockError != "" {
		t.Fatalf("plausible rollback state is wrong: %+v", status)
	}
	if !manager.effectiveNowUTC().Equal(highWater) {
		t.Fatalf("freshness did not advance from the trusted high-water mark: %v", manager.effectiveNowUTC())
	}
	if err := manager.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "wall-clock rollback") {
		t.Fatalf("sync did not refuse to run on a rolled-back clock: %v", err)
	}
}

// The persistence path signs and hardens the state; a modified timestamp fails
// authentication on the next load.
func TestClockStatePersistenceRoundTripAndTamperRejection(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := manager.persistFeedClock(now); err != nil {
		t.Fatalf("persistFeedClock: %v", err)
	}
	loaded, err := loadFeedClock(root, clockKeyForTest(t, root))
	if err != nil || !loaded.Equal(now) {
		t.Fatalf("authenticated clock round trip failed: %v %v", loaded, err)
	}
	raw, err := os.ReadFile(feedClockPath(root))
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), now.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano), 1)
	if tampered == string(raw) {
		t.Fatalf("test could not find the clock timestamp: %s", raw)
	}
	if err := os.WriteFile(feedClockPath(root), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFeedClock(root, clockKeyForTest(t, root)); err == nil {
		t.Fatal("tampered clock timestamp was accepted")
	} else if !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("tampered clock timestamp failure is not explicit: %v", err)
	}
}
