// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

func TestEngineThreatIntelPollingValidationPersistenceAndStatus(t *testing.T) {
	root := t.TempDir()
	writeCachedBlockingFeed(t, root)
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	feeds, err := threatintel.NewManager(filepath.Join(root, "intelligence"))
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{root: root, ledger: ledger, feeds: feeds, mode: "guarded", intelligenceWake: make(chan struct{}, 1)}
	ctx := context.Background()

	defaults := engine.ThreatIntelPolling()
	if defaults.IntervalSeconds != int(threatintel.DefaultPollInterval/time.Second) || defaults.Source != "DEFAULT" {
		t.Fatalf("default polling config is wrong: %+v", defaults)
	}
	minimum := int(threatintel.MinPollInterval / time.Second)
	maximum := int(threatintel.MaxPollInterval / time.Second)
	for _, interval := range []int{0, -1, minimum - 1, maximum + 1} {
		if _, err := engine.SetThreatIntelPolling(ctx, interval); err == nil {
			t.Fatalf("out-of-range polling interval %d accepted", interval)
		}
		if got := engine.ThreatIntelPolling(); got.IntervalSeconds != defaults.IntervalSeconds {
			t.Fatalf("rejected polling interval %d changed the effective policy: %+v", interval, got)
		}
	}
	if _, err := engine.SetThreatIntelPolling(nil, 3600); err == nil {
		t.Fatal("polling update accepted a nil context")
	}

	updated, err := engine.SetThreatIntelPolling(ctx, 3600)
	if err != nil {
		t.Fatalf("valid polling interval rejected: %v", err)
	}
	if updated.IntervalSeconds != 3600 || updated.Source != "PERSISTED" || updated.UpdatedUTC.IsZero() {
		t.Fatalf("updated polling config incomplete: %+v", updated)
	}
	if len(engine.intelligenceWake) == 0 {
		t.Fatal("polling update did not wake the feed scheduler")
	}
	status := engine.Status()
	if status.ThreatIntelPolling.IntervalSeconds != 3600 || status.ThreatIntelligence.PollingIntervalSeconds != 3600 || status.ThreatIntelligence.PollingIntervalSource != "PERSISTED" {
		t.Fatalf("status did not project the polling policy: %+v / %+v", status.ThreatIntelPolling, status.ThreatIntelligence)
	}

	// Simulated restart: the manager restores the persisted interval.
	restartedLedger, err := evidence.Open(filepath.Join(root, "restarted-evidence.jsonl"), filepath.Join(root, "restarted-evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	restartedFeeds, err := threatintel.NewManager(filepath.Join(root, "intelligence"))
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Engine{root: root, ledger: restartedLedger, feeds: restartedFeeds, mode: "guarded"}
	if got := restarted.ThreatIntelPolling(); got.IntervalSeconds != 3600 || got.Source != "PERSISTED" {
		t.Fatalf("polling policy did not survive restart: %+v", got)
	}
}
