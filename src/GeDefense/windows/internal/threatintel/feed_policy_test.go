// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func writeFeedPolicyTestSnapshot(t *testing.T, root, key string, indicators []string) {
	t.Helper()
	source, exists := sourceByKey(key)
	if !exists {
		t.Fatalf("test feed %q is not in the catalog", key)
	}
	sorted := append([]string(nil), indicators...)
	sort.Strings(sorted)
	snapshot := sourceSnapshot{
		SchemaVersion:    SchemaVersion,
		Key:              key,
		GeneratedUTC:     time.Now().UTC(),
		Action:           source.Action,
		Attribution:      Attribution{Name: source.Name, URL: source.URL},
		GenerationSHA256: digestIndicators(key, source.Action, sorted),
		Indicators:       sorted,
	}
	if err := writeSourceSnapshot(root, snapshot); err != nil {
		t.Fatalf("write cached snapshot %s: %v", key, err)
	}
}

// newFeedPolicyTestManager seeds validated last-known-good data for every
// default BLOCK feed plus one CORRELATE_ONLY feed, then starts the real manager
// without any network access.
func newFeedPolicyTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "intelligence")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFeedPolicyTestSnapshot(t, root, "feodo", []string{"45.155.205.0/24"})
	writeFeedPolicyTestSnapshot(t, root, "spamhaus_drop_v4", []string{"46.155.205.0/24"})
	writeFeedPolicyTestSnapshot(t, root, "spamhaus_drop_v6", []string{"2a02:1234::/32"})
	writeFeedPolicyTestSnapshot(t, root, "firehol_l1", []string{"47.155.205.0/24"})
	writeFeedPolicyTestSnapshot(t, root, "cins_army", []string{"48.155.205.0/24"})
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	return manager, root
}

func feedPolicyTestDigest() string {
	return strings.Repeat("a", 64)
}

func feedPolicyEntry(t *testing.T, snapshot FeedPolicySnapshot, key string) FeedPolicyEntry {
	t.Helper()
	for _, entry := range snapshot.Entries {
		if entry.FeedKey == key {
			return entry
		}
	}
	t.Fatalf("feed %q missing from feed policy snapshot", key)
	return FeedPolicyEntry{}
}

func TestFeedPolicyDefaultsExposeCatalogAuthority(t *testing.T) {
	manager, _ := newFeedPolicyTestManager(t)
	policy := manager.FeedPolicy()
	if policy.StoreState != feedPolicySourceDefault || policy.StoreError != "" {
		t.Fatalf("default store state is wrong: %+v", policy)
	}
	if policy.SchemaVersion != FeedPolicySchemaVersion || len(policy.Entries) != len(catalog) {
		t.Fatalf("feed policy snapshot incomplete: %+v", policy)
	}
	if policy.EnforcementChanged || policy.BlockingIndicators <= 0 || len(policy.EnforcementGeneration) != 64 {
		t.Fatalf("default policy enforcement projection is wrong: %+v", policy)
	}
	if policy.Limits.MaxOverrides != len(catalog) || len(policy.Limits.AllowedActions) != 3 || policy.Limits.MaximumFeedIDBytes != MaximumFeedIDBytes {
		t.Fatalf("published feed policy limits are wrong: %+v", policy.Limits)
	}
	if policy.BlockingFeedsTotal != 4 || policy.BlockingFeedsReady != 4 {
		t.Fatalf("default blocking coverage is wrong: total=%d ready=%d", policy.BlockingFeedsTotal, policy.BlockingFeedsReady)
	}
	for _, entry := range policy.Entries {
		if entry.ConfiguredAction != entry.DefaultAction || entry.EffectiveAction != entry.DefaultAction || entry.Source != feedPolicySourceDefault || entry.EnforcementImpact != "NONE" {
			t.Fatalf("default feed entry claims an override: %+v", entry)
		}
		if (entry.EffectiveAction == ActionBlock) != entry.Blocking {
			t.Fatalf("blocking flag inconsistent: %+v", entry)
		}
	}
	status := manager.Status()
	if status.FeedPolicySource != feedPolicySourceDefault || status.FeedPolicyOverrides != 0 {
		t.Fatalf("status did not project the feed policy store: %+v", status)
	}
	enriched := false
	for _, feed := range status.Feeds {
		if feed.Key == "cins_army" {
			enriched = true
			if feed.DefaultAction != ActionCorrelateOnly || feed.ConfiguredAction != ActionCorrelateOnly || feed.EffectiveAction != ActionCorrelateOnly || feed.ActionSource != feedPolicySourceDefault {
				t.Fatalf("status feed authority projection is wrong: %+v", feed)
			}
		}
	}
	if !enriched {
		t.Fatal("status did not contain the expected feed")
	}
}

func TestFeedPolicyPromotionIsAppliedToCompilerAndPersists(t *testing.T) {
	manager, root := newFeedPolicyTestManager(t)
	before := manager.FeedPolicy()
	block := ActionBlock
	updated, err := manager.SetFeedActions([]FeedActionChange{{FeedKey: "cins_army", Action: &block}}, feedPolicyTestDigest(), time.Now().UTC())
	if err != nil {
		t.Fatalf("promoting a validated feed to BLOCK failed: %v", err)
	}
	entry := feedPolicyEntry(t, updated, "cins_army")
	if entry.ConfiguredAction != ActionBlock || entry.EffectiveAction != ActionBlock || !entry.Blocking || entry.Source != feedPolicyEntrySource {
		t.Fatalf("promoted feed authority is wrong: %+v", entry)
	}
	if entry.EnforcementImpact != "ADDS_BLOCK" || !updated.EnforcementChanged {
		t.Fatalf("enforcement change was not reported: impact=%q changed=%v", entry.EnforcementImpact, updated.EnforcementChanged)
	}
	if updated.EnforcementGeneration == before.EnforcementGeneration || len(updated.EnforcementGeneration) != 64 {
		t.Fatal("promotion did not change the enforcement generation")
	}
	if updated.BlockingFeedsTotal != 5 || updated.BlockingFeedsReady != 5 {
		t.Fatalf("promoted blocking coverage is wrong: %+v", updated)
	}
	// The effective mode must drive the real lookup/blocking decision.
	match := manager.Lookup(mustFeedPolicyAddr(t, "48.155.205.7"))
	if !match.Found || match.Action != ActionBlock {
		t.Fatalf("promoted feed did not become a blocking decision: %+v", match)
	}
	sources := strings.Join(match.Sources, ",")
	if !strings.Contains(sources, "cins_army") {
		t.Fatalf("promoted feed lost attribution: %+v", match)
	}
	// Downloaded feed data keeps the immutable catalog authority.
	cinsSource, _ := sourceByKey("cins_army")
	stored, err := readSourceSnapshot(root, cinsSource)
	if err != nil {
		t.Fatalf("read cached snapshot: %v", err)
	}
	if stored.Action != ActionCorrelateOnly {
		t.Fatalf("override rewrote downloaded feed data authority: %+v", stored.Action)
	}
	if _, err := os.Stat(filepath.Join(root, feedPolicyFileName)); err != nil {
		t.Fatalf("feed policy store was not persisted: %v", err)
	}

	// Restart: the persisted override must be reloaded and applied to the
	// compiler before any synchronization happens.
	restarted, err := NewManager(root)
	if err != nil {
		t.Fatalf("restart manager: %v", err)
	}
	restartedPolicy := restarted.FeedPolicy()
	if restartedPolicy.StoreState != feedPolicySourcePersisted || feedPolicyEntry(t, restartedPolicy, "cins_army").EffectiveAction != ActionBlock {
		t.Fatalf("restart did not restore the effective override: %+v", restartedPolicy)
	}
	restartedMatch := restarted.Lookup(mustFeedPolicyAddr(t, "48.155.205.7"))
	if !restartedMatch.Found || restartedMatch.Action != ActionBlock {
		t.Fatalf("restart did not apply the override to the compiler: %+v", restartedMatch)
	}
}

func TestFeedPolicyDowngradeIsExplicitAndAuditable(t *testing.T) {
	manager, root := newFeedPolicyTestManager(t)
	before := manager.FeedPolicy()
	correlate := ActionCorrelateOnly
	updated, err := manager.SetFeedActions([]FeedActionChange{{FeedKey: "feodo", Action: &correlate}}, feedPolicyTestDigest(), time.Now().UTC())
	if err != nil {
		t.Fatalf("downgrading a BLOCK feed failed: %v", err)
	}
	entry := feedPolicyEntry(t, updated, "feodo")
	if entry.ConfiguredAction != ActionCorrelateOnly || entry.Blocking || entry.EnforcementImpact != "REMOVES_BLOCK" {
		t.Fatalf("downgraded feed authority is wrong: %+v", entry)
	}
	if updated.EnforcementGeneration == before.EnforcementGeneration {
		t.Fatal("downgrade did not change the enforcement generation")
	}
	if updated.BlockingFeedsTotal != 3 || updated.BlockingFeedsReady != 3 {
		t.Fatalf("downgraded blocking coverage is wrong: %+v", updated)
	}
	match := manager.Lookup(mustFeedPolicyAddr(t, "45.155.205.7"))
	if !match.Found || match.Action != ActionCorrelateOnly {
		t.Fatalf("downgraded feed still blocks: %+v", match)
	}
	feodoSource, _ := sourceByKey("feodo")
	stored, err := readSourceSnapshot(root, feodoSource)
	if err != nil || stored.Action != ActionBlock {
		t.Fatalf("downgrade rewrote downloaded feed data: %+v err=%v", stored.Action, err)
	}
	restarted, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := feedPolicyEntry(t, restarted.FeedPolicy(), "feodo"); got.EffectiveAction != ActionCorrelateOnly {
		t.Fatalf("downgrade did not survive restart: %+v", got)
	}
}

func TestFeedPolicyResetToDefaultRemovesOverride(t *testing.T) {
	manager, root := newFeedPolicyTestManager(t)
	block := ActionBlock
	if _, err := manager.SetFeedActions([]FeedActionChange{{FeedKey: "cins_army", Action: &block}}, feedPolicyTestDigest(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	reset, err := manager.SetFeedActions([]FeedActionChange{{FeedKey: "cins_army"}}, feedPolicyTestDigest(), time.Now().UTC())
	if err != nil {
		t.Fatalf("reset-to-default failed: %v", err)
	}
	entry := feedPolicyEntry(t, reset, "cins_army")
	if entry.Source != feedPolicySourceDefault || entry.ConfiguredAction != ActionCorrelateOnly || entry.EffectiveAction != ActionCorrelateOnly {
		t.Fatalf("reset did not restore the catalog authority: %+v", entry)
	}
	if match := manager.Lookup(mustFeedPolicyAddr(t, "48.155.205.7")); match.Action != ActionCorrelateOnly {
		t.Fatalf("reset still blocks: %+v", match)
	}
	// The empty persisted store is explicit; catalog defaults are effective.
	if reset.StoreState != feedPolicySourcePersisted {
		t.Fatalf("reset store state is wrong: %+v", reset.StoreState)
	}
	contents, err := os.ReadFile(filepath.Join(root, feedPolicyFileName))
	if err != nil {
		t.Fatalf("read reset store: %v", err)
	}
	var state feedPolicyState
	if err := json.Unmarshal(contents, &state); err != nil || len(state.Overrides) != 0 {
		t.Fatalf("reset store is not an explicit empty override list: %v %+v", err, state)
	}
}

func TestFeedPolicyFailClosedTransitions(t *testing.T) {
	manager, root := newFeedPolicyTestManager(t)
	before := manager.FeedPolicy()
	block := ActionBlock
	correlate := ActionCorrelateOnly

	// Removing every blocking feed would leave no compiled enforcement.
	changes := make([]FeedActionChange, 0, 4)
	for _, key := range []string{"feodo", "spamhaus_drop_v4", "spamhaus_drop_v6", "firehol_l1"} {
		action := correlate
		changes = append(changes, FeedActionChange{FeedKey: key, Action: &action})
	}
	if _, err := manager.SetFeedActions(changes, feedPolicyTestDigest(), time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "remove all blocking") {
		t.Fatalf("all-blocking removal was not rejected fail-closed: %v", err)
	}
	rejected := manager.FeedPolicy()
	if rejected.EnforcementGeneration != before.EnforcementGeneration || rejected.StoreState != feedPolicySourceDefault {
		t.Fatalf("rejected transition changed enforcement or store: %+v", rejected)
	}
	if _, err := os.Stat(filepath.Join(root, feedPolicyFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected transition persisted a policy: %v", err)
	}

	// Promoting a feed without validated indicators would claim blocking
	// coverage that cannot be compiled; it must be rejected. ipsum is
	// CORRELATE_ONLY and has no cached data in this fixture.
	if _, err := manager.SetFeedActions([]FeedActionChange{{FeedKey: "ipsum", Action: &block}}, feedPolicyTestDigest(), time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "validated indicators") {
		t.Fatalf("promotion without validated data was not rejected: %v", err)
	}

	invalid := []struct {
		name    string
		changes []FeedActionChange
		digest  string
	}{
		{"unknown-feed", []FeedActionChange{{FeedKey: "not_a_feed", Action: &block}}, feedPolicyTestDigest()},
		{"empty-changes", nil, feedPolicyTestDigest()},
		{"bad-digest", []FeedActionChange{{FeedKey: "cins_army", Action: &block}}, "zz"},
		{"invalid-action", []FeedActionChange{{FeedKey: "cins_army", Action: actionPointer(Action("BLOCK_ALL"))}}, feedPolicyTestDigest()},
		{"duplicate", []FeedActionChange{{FeedKey: "cins_army", Action: &block}, {FeedKey: "cins_army", Action: &correlate}}, feedPolicyTestDigest()},
	}
	for _, testCase := range invalid {
		if _, err := manager.SetFeedActions(testCase.changes, testCase.digest, time.Now().UTC()); err == nil {
			t.Fatalf("invalid feed policy change %q was accepted", testCase.name)
		}
	}
	if got := manager.FeedPolicy(); got.EnforcementGeneration != before.EnforcementGeneration || got.StoreState != feedPolicySourceDefault {
		t.Fatalf("invalid changes mutated policy state: %+v", got)
	}
}

func TestFeedPolicyWithoutValidatedDataPersistsIntentButClaimsNoEnforcement(t *testing.T) {
	root := filepath.Join(t.TempDir(), "intelligence")
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	block := ActionBlock
	preSync, err := manager.SetFeedActions([]FeedActionChange{{FeedKey: "cins_army", Action: &block}}, feedPolicyTestDigest(), time.Now().UTC())
	if err != nil {
		t.Fatalf("pre-sync intent was rejected: %v", err)
	}
	if preSync.EnforcementGeneration != "" || preSync.BlockingIndicators != 0 {
		t.Fatalf("pre-sync policy fabricated enforcement: %+v", preSync)
	}
	if entry := feedPolicyEntry(t, preSync, "cins_army"); entry.EffectiveAction != ActionBlock || entry.Indicators != 0 {
		t.Fatalf("pre-sync authority is unclear: %+v", entry)
	}
	if preSync.StoreState != feedPolicySourcePersisted {
		t.Fatalf("pre-sync intent was not persisted: %+v", preSync)
	}
}

func TestFeedPolicyCorruptStoreFallsBackAndPreservesForensics(t *testing.T) {
	root := filepath.Join(t.TempDir(), "intelligence")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte(`{"schemaVersion":1,"overrides":[{"feedKey":"feodo","action":"GOD_MODE","updatedUtc":"2026-10-22T00:00:00Z"}],"updatedUtc":"2026-10-22T00:00:00Z"}`)
	if err := os.WriteFile(filepath.Join(root, feedPolicyFileName), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("corrupt store broke manager startup: %v", err)
	}
	policy := manager.FeedPolicy()
	if policy.StoreState != feedPolicySourceInvalid || policy.StoreError == "" {
		t.Fatalf("corrupt store was not surfaced: %+v", policy)
	}
	if policy.EnforcementChanged || policy.BlockingIndicators != 0 {
		t.Fatalf("corrupt store fabricated authority: %+v", policy)
	}
	for _, entry := range policy.Entries {
		if entry.Source != feedPolicySourceDefault || entry.EffectiveAction != entry.DefaultAction {
			t.Fatalf("corrupt store affected effective authority: %+v", entry)
		}
	}
	preserved, err := os.ReadFile(filepath.Join(root, feedPolicyFileName))
	if err != nil || string(preserved) != string(corrupt) {
		t.Fatalf("corrupt store was not preserved for forensics: %v", err)
	}
	// An explicit operator update replaces the corrupt store.
	block := ActionBlock
	if _, err := manager.SetFeedActions([]FeedActionChange{{FeedKey: "cins_army", Action: &block}}, feedPolicyTestDigest(), time.Now().UTC()); err != nil {
		t.Fatalf("operator recovery from corrupt store failed: %v", err)
	}
	if got := manager.FeedPolicy(); got.StoreState != feedPolicySourcePersisted || got.StoreError != "" {
		t.Fatalf("recovered store state is wrong: %+v", got)
	}
}

func TestFeedPolicyRejectsOversizedOrNonRegularStore(t *testing.T) {
	root := filepath.Join(t.TempDir(), "intelligence")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, feedPolicyFileName), []byte(strings.Repeat("x", maximumFeedPolicyBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	if policy := manager.FeedPolicy(); policy.StoreState != feedPolicySourceInvalid {
		t.Fatalf("oversized store was trusted: %+v", policy)
	}

	root = filepath.Join(t.TempDir(), "intelligence")
	if err := os.MkdirAll(filepath.Join(root, feedPolicyFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err = NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	if policy := manager.FeedPolicy(); policy.StoreState != feedPolicySourceInvalid || !strings.Contains(policy.StoreError, "regular non-symlink") {
		t.Fatalf("non-regular store was not rejected explicitly: %+v", policy)
	}
}

func TestFeedPolicyPreservesProtectedNetworkSubtraction(t *testing.T) {
	manager, _ := newFeedPolicyTestManager(t)
	protected, err := manager.SetProtectedPrefixes([]string{"45.155.205.42/32"})
	if err != nil {
		t.Fatalf("set protected prefixes: %v", err)
	}
	if protected.GenerationSHA256 == "" {
		t.Fatal("protected policy generation missing")
	}
	block := ActionBlock
	if _, err := manager.SetFeedActions([]FeedActionChange{{FeedKey: "cins_army", Action: &block}}, feedPolicyTestDigest(), time.Now().UTC()); err != nil {
		t.Fatalf("promotion with protected networks failed: %v", err)
	}
	index := manager.index.Load()
	if index == nil {
		t.Fatal("index missing")
	}
	protectedAddr := mustFeedPolicyAddr(t, "45.155.205.42")
	for _, indicator := range index.blockIndicators {
		prefix, err := parseThreatToken(indicator)
		if err != nil {
			t.Fatalf("compiled indicator invalid: %v", err)
		}
		if prefix.Contains(protectedAddr) {
			t.Fatalf("protected network leaked into enforcement after feed policy change: %s (all=%v protected=%v)", indicator, index.blockIndicators, protected.Prefixes)
		}
	}
	if manager.Lookup(mustFeedPolicyAddr(t, "48.155.205.7")).Action != ActionBlock {
		t.Fatal("promoted correlated feed lost effective blocking authority")
	}
}

func actionPointer(action Action) *Action { return &action }

func mustFeedPolicyAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	parsed, err := parseThreatToken(value)
	if err != nil {
		t.Fatalf("invalid test address %q: %v", value, err)
	}
	return parsed.Addr()
}
