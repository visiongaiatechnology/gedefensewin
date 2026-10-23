// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newPollingTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	return manager, root
}

func TestPollingDefaultsPreserveFeedSemantics(t *testing.T) {
	manager, _ := newPollingTestManager(t)
	defaultSeconds := int(SyncInterval / time.Second)
	polling := manager.PollingConfig()
	if polling.IntervalSeconds != defaultSeconds || polling.DefaultIntervalSeconds != defaultSeconds || polling.Source != pollingSourceDefault {
		t.Fatalf("unexpected default polling config: %+v", polling)
	}
	if polling.MinIntervalSeconds != int(MinPollInterval/time.Second) || polling.MaxIntervalSeconds != int(MaxPollInterval/time.Second) {
		t.Fatalf("published polling bounds are wrong: %+v", polling)
	}
	if SyncInterval != 12*time.Hour || FailureRetryInterval != 15*time.Minute {
		t.Fatalf("feed manager cadence constants changed: sync=%v retry=%v", SyncInterval, FailureRetryInterval)
	}
	status := manager.Status()
	if status.PollingIntervalSeconds != defaultSeconds || status.PollingIntervalSource != pollingSourceDefault || status.PollingIntervalDefaultSeconds != defaultSeconds {
		t.Fatalf("status does not project the polling policy: %+v", status)
	}
	// No successful synchronization has happened yet, so the next automatic
	// poll is immediately due instead of carrying an invented timestamp.
	if !status.NextSyncUTC.IsZero() || !polling.NextPollUTC.IsZero() {
		t.Fatalf("unstarted manager advertised a fabricated next poll: %+v", polling)
	}
	var unavailable *Manager
	if fallback := unavailable.PollingConfig(); fallback.IntervalSeconds != defaultSeconds || fallback.Source != pollingSourceDefault {
		t.Fatalf("nil manager did not expose the default polling policy: %+v", fallback)
	}
}

func TestSetPollingIntervalValidatesAndPersists(t *testing.T) {
	manager, root := newPollingTestManager(t)
	defaultSeconds := int(SyncInterval / time.Second)
	minimum := int(MinPollInterval / time.Second)
	maximum := int(MaxPollInterval / time.Second)
	for _, seconds := range []int{0, -1, minimum - 1, maximum + 1, 1 << 30} {
		if _, err := manager.SetPollingIntervalSeconds(seconds); err == nil {
			t.Fatalf("out-of-range polling interval %d was accepted", seconds)
		}
		if got := manager.PollingConfig().IntervalSeconds; got != defaultSeconds {
			t.Fatalf("rejected interval %d replaced the active interval with %d", seconds, got)
		}
	}

	activated, err := manager.SetPollingIntervalSeconds(3600)
	if err != nil {
		t.Fatalf("valid polling interval rejected: %v", err)
	}
	if activated.IntervalSeconds != 3600 || activated.Source != pollingSourcePersisted || activated.UpdatedUTC.IsZero() {
		t.Fatalf("activated polling config is incomplete: %+v", activated)
	}
	if _, statErr := os.Stat(filepath.Join(root, "polling.json")); statErr != nil {
		t.Fatalf("polling policy was not persisted: %v", statErr)
	}
	for _, boundary := range []int{minimum, maximum} {
		if _, err := manager.SetPollingIntervalSeconds(boundary); err != nil {
			t.Fatalf("documented boundary interval %d rejected: %v", boundary, err)
		}
		if got := manager.PollingConfig().IntervalSeconds; got != boundary {
			t.Fatalf("boundary interval %d not activated: %d", boundary, got)
		}
	}
}

func TestPollingIntervalSurvivesManagerRestart(t *testing.T) {
	root := t.TempDir()
	first, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.SetPollingIntervalSeconds(1800); err != nil {
		t.Fatal(err)
	}
	second, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	polling := second.PollingConfig()
	if polling.IntervalSeconds != 1800 || polling.Source != pollingSourcePersisted || polling.UpdatedUTC.IsZero() {
		t.Fatalf("polling policy did not survive a manager restart: %+v", polling)
	}
}

func TestInvalidPersistedPollingPolicyFallsBackToDefault(t *testing.T) {
	invalidState := []string{
		"not-json",
		`{"schemaVersion":0,"intervalSeconds":3600,"updatedUtc":"2026-10-22T08:00:00Z"}`,
		`{"schemaVersion":1,"intervalSeconds":60,"updatedUtc":"2026-10-22T08:00:00Z"}`,
		`{"schemaVersion":1,"intervalSeconds":-5,"updatedUtc":"2026-10-22T08:00:00Z"}`,
		`{"schemaVersion":1,"intervalSeconds":86400,"updatedUtc":"2026-10-22T08:00:00Z","unknown":true}`,
		`{} {}`,
		strings.Repeat("x", maximumPollingStateBytes+1),
	}
	minimum := int(MinPollInterval / time.Second)
	for _, body := range invalidState {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "polling.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		manager, err := NewManager(root)
		if err != nil {
			t.Fatalf("invalid polling policy broke manager startup: %v", err)
		}
		polling := manager.PollingConfig()
		if polling.IntervalSeconds != int(DefaultPollInterval/time.Second) || polling.Source != pollingSourceInvalid {
			t.Fatalf("invalid persisted policy was trusted: %+v (body %q)", polling, body)
		}
		if polling.MinIntervalSeconds != minimum {
			t.Fatalf("published minimum interval missing after fallback: %+v", polling)
		}
		if polling.Error == "" || manager.Status().PollingIntervalSource != pollingSourceInvalid {
			t.Fatalf("invalid persisted policy was not surfaced: %+v", polling)
		}
		// A rejected file must not block a later valid operator update.
		if _, err := manager.SetPollingIntervalSeconds(3600); err != nil {
			t.Fatalf("valid interval could not replace invalid persisted policy: %v", err)
		}
		if got := manager.PollingConfig(); got.IntervalSeconds != 3600 || got.Source != pollingSourcePersisted || got.Error != "" {
			t.Fatalf("recovered polling policy is inconsistent: %+v", got)
		}
	}
}

func TestSetPollingIntervalRecomputesNextPoll(t *testing.T) {
	manager, _ := newPollingTestManager(t)
	attempt := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	manager.statusMu.Lock()
	manager.status.LastAttemptUTC = attempt
	manager.status.LastSuccessUTC = attempt
	manager.status.NextSyncUTC = attempt.Add(SyncInterval)
	manager.statusMu.Unlock()

	if _, err := manager.SetPollingIntervalSeconds(3600); err != nil {
		t.Fatal(err)
	}
	if got := manager.Status().NextSyncUTC; !got.Equal(attempt.Add(time.Hour)) {
		t.Fatalf("next poll was not recomputed from the new interval: %v", got)
	}
	if got := manager.PollingConfig(); !got.NextPollUTC.Equal(attempt.Add(time.Hour)) || !got.LastAttemptUTC.Equal(attempt) || !got.LastSyncUTC.Equal(attempt) {
		t.Fatalf("polling config timestamps are inconsistent: %+v", got)
	}

	if _, err := manager.SetPollingIntervalSeconds(int(MinPollInterval / time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := manager.Status().NextSyncUTC; !got.Equal(attempt.Add(MinPollInterval)) {
		t.Fatalf("shortened interval did not take effect immediately: %v", got)
	}
}
