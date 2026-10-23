// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

// writeFeedPolicyCachedSource writes a validated last-known-good snapshot for a
// catalog feed without any network access.
func writeFeedPolicyCachedSource(t *testing.T, intelRoot, key string, indicators []string) {
	t.Helper()
	var source threatintel.Source
	found := false
	for _, candidate := range threatintel.Catalog() {
		if candidate.Key == key {
			source, found = candidate, true
			break
		}
	}
	if !found {
		t.Fatalf("feed %q missing from catalog", key)
	}
	sorted := append([]string(nil), indicators...)
	sort.Strings(sorted)
	digest := sha256.Sum256([]byte(key + "\n" + string(source.Action) + "\n" + strings.Join(sorted, "\n")))
	payload, err := json.Marshal(map[string]any{
		"schemaVersion":    threatintel.SchemaVersion,
		"key":              key,
		"generatedUtc":     time.Now().UTC().Format(time.RFC3339Nano),
		"action":           string(source.Action),
		"attribution":      map[string]any{"name": source.Name, "url": source.URL},
		"generationSha256": hex.EncodeToString(digest[:]),
		"indicators":       sorted,
	})
	if err != nil {
		t.Fatal(err)
	}
	sources := filepath.Join(intelRoot, "sources")
	if err := os.MkdirAll(sources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sources, key+".json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeFeedPolicyProtection exercises the real WFP verification contract without
// touching a Windows firewall. It echoes the current desired generation so the
// engine verification path is exercised exactly like production.
type fakeFeedPolicyProtection struct {
	feeds *threatintel.Manager
	fail  bool
	calls int
}

func (f *fakeFeedPolicyProtection) ApplyThreatIntelligence(_ context.Context, _ string, generation string, indicators int) (FirewallResult, error) {
	f.calls++
	if f.fail {
		return FirewallResult{}, errors.New("injected WFP generation failure")
	}
	status := f.feeds.Status()
	return FirewallResult{
		TimestampUTC:         time.Now().UTC().Format(time.RFC3339Nano),
		Generation:           generation,
		Indicators:           indicators,
		Rules:                4,
		Shards:               1,
		Mode:                 "dynamic-keyword",
		ProtectionGeneration: status.ProtectionGeneration,
		ProtectedPrefixCount: status.ProtectedPrefixes,
	}, nil
}

func (f *fakeFeedPolicyProtection) Applications(context.Context, string, string) (ApplicationAllowResult, error) {
	return ApplicationAllowResult{}, nil
}

func (f *fakeFeedPolicyProtection) ApplyAppControl(context.Context, string) (AppControlResult, error) {
	return AppControlResult{}, nil
}

func (f *fakeFeedPolicyProtection) Apply(context.Context, string) (ProtectionResult, error) {
	return ProtectionResult{}, nil
}

func newFeedPolicyEngine(t *testing.T, failWFP bool) (*Engine, *fakeFeedPolicyProtection, string) {
	t.Helper()
	root := t.TempDir()
	intelRoot := filepath.Join(root, "intelligence")
	writeFeedPolicyCachedSource(t, intelRoot, "feodo", []string{"45.155.205.0/24"})
	writeFeedPolicyCachedSource(t, intelRoot, "spamhaus_drop_v4", []string{"46.155.205.0/24"})
	writeFeedPolicyCachedSource(t, intelRoot, "spamhaus_drop_v6", []string{"2a02:1234::/32"})
	writeFeedPolicyCachedSource(t, intelRoot, "firehol_l1", []string{"47.155.205.0/24"})
	writeFeedPolicyCachedSource(t, intelRoot, "cins_army", []string{"48.155.205.0/24"})
	feeds, err := threatintel.NewManager(intelRoot)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	protection := &fakeFeedPolicyProtection{feeds: feeds, fail: failWFP}
	engine := &Engine{
		root: root, ledger: ledger, feeds: feeds, protection: protection, mode: "guarded",
		kineticMonitor: kinetic.NewMonitor(), intelligenceWake: make(chan struct{}, 1),
		recentProcesses: make(map[uint32]recentProcess, 8),
	}
	engine.loadPolicySettings()
	return engine, protection, root
}

func feedPolicyRecordResults(t *testing.T, ledger *evidence.Ledger) []string {
	t.Helper()
	records, err := ledger.Snapshot(200)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]string, 0, len(records))
	for _, record := range records {
		if record.Kind == "threat-intelligence.feed-policy" {
			result = append(result, record.Action+"/"+record.Result)
		}
	}
	return result
}

func TestEngineFeedPolicyInitialStateIsHonest(t *testing.T) {
	engine, _, _ := newFeedPolicyEngine(t, false)
	policy := engine.FeedPolicy()
	if policy.StoreState != "DEFAULT" || policy.SchemaVersion != threatintel.FeedPolicySchemaVersion {
		t.Fatalf("initial feed policy state is wrong: %+v", policy)
	}
	if !policy.Pending || policy.WFPVerified || policy.EnforcementState == "VERIFIED" {
		t.Fatalf("unverified enforcement was reported effective: %+v", policy)
	}
	if policy.EnforcementGeneration == "" || policy.WFPVerified {
		t.Fatalf("initial enforcement generation expectation is wrong: %+v", policy)
	}
	if policy.Limits.MaxUpdates != maximumFeedPolicyUpdates || policy.Limits.MinimumReasonBytes != minimumFeedPolicyReasonBytes || len(policy.Limits.AllowedActions) != 3 {
		t.Fatalf("engine feed policy limits are wrong: %+v", policy.Limits)
	}
	blockingFeeds := 0
	for _, feed := range policy.Feeds {
		if feed.Blocking {
			blockingFeeds++
			if feed.Enforcement != "PENDING_WFP_VERIFICATION" {
				t.Fatalf("unverified blocking feed claims verified authority: %+v", feed)
			}
		}
	}
	if blockingFeeds != 4 || len(policy.Feeds) != 9 {
		t.Fatalf("initial feed inventory is wrong: %d blocking / %d feeds", blockingFeeds, len(policy.Feeds))
	}
	if len(policy.Warnings) == 0 {
		t.Fatal("pending enforcement state has no warning")
	}
}

func TestEngineFeedPolicyPromotionVerifiedAndAudited(t *testing.T) {
	engine, protection, root := newFeedPolicyEngine(t, false)
	ctx := context.Background()
	updated, err := engine.SetFeedActions(ctx, []FeedActionUpdate{{FeedID: "cins_army", Action: "BLOCK"}}, "Operator promotes CINS Army to blocking for a pilot")
	if err != nil {
		t.Fatalf("validated promotion rejected: %v", err)
	}
	if !updated.WFPVerified || updated.Pending || updated.EnforcementState != "VERIFIED" {
		t.Fatalf("verified promotion was not reported effective: %+v", updated)
	}
	if !updated.EnforcementChanged || updated.PreviousEnforcementGeneration == "" || updated.ActiveGeneration != updated.EnforcementGeneration {
		t.Fatalf("enforcement change evidence is wrong: %+v", updated)
	}
	if protection.calls != 1 {
		t.Fatalf("WFP generation was not applied exactly once: %d", protection.calls)
	}
	var promoted FeedPolicyEntry
	for _, feed := range updated.Feeds {
		if feed.FeedID == "cins_army" {
			promoted = feed
		}
	}
	if promoted.ConfiguredAction != threatintel.ActionBlock || promoted.EffectiveAction != threatintel.ActionBlock || promoted.Enforcement != "VERIFIED_BLOCK" || promoted.ActionSource != "OVERRIDE" {
		t.Fatalf("promoted feed projection is wrong: %+v", promoted)
	}
	records := feedPolicyRecordResults(t, engine.ledger)
	requestRecorded := false
	verified := false
	for _, record := range records {
		if strings.HasPrefix(record, "request/") {
			requestRecorded = true
		}
		if record == "change/verified" {
			verified = true
		}
	}
	if !requestRecorded {
		t.Fatalf("feed policy request was not evidenced: %v", records)
	}
	if !verified {
		t.Fatalf("verified feed policy change was not evidenced: %v", records)
	}
	// Persistence: the override and its effective blocking decision survive a
	// restart before any new synchronization.
	restartedFeeds, err := threatintel.NewManager(filepath.Join(root, "intelligence"))
	if err != nil {
		t.Fatal(err)
	}
	restartedLedger, err := evidence.Open(filepath.Join(root, "restarted-evidence.jsonl"), filepath.Join(root, "restarted-evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Engine{root: root, ledger: restartedLedger, feeds: restartedFeeds, protection: &fakeFeedPolicyProtection{feeds: restartedFeeds}, mode: "guarded"}
	restartedPolicy := restarted.FeedPolicy()
	foundPromoted := false
	for _, feed := range restartedPolicy.Feeds {
		if feed.FeedID == "cins_army" {
			foundPromoted = true
			if feed.ConfiguredAction != threatintel.ActionBlock || feed.ActionSource != "OVERRIDE" {
				t.Fatalf("restart lost the configured override: %+v", feed)
			}
		}
	}
	if !foundPromoted {
		t.Fatal("restart lost the promoted feed")
	}
	if !restartedPolicy.Pending {
		t.Fatal("restart reported blocking as verified before a WFP verification")
	}
	if err := restarted.applyThreatEnforcement(ctx, restarted.feeds.Status()); err != nil {
		t.Fatalf("restarted enforcement verification failed: %v", err)
	}
	if verifiedPolicy := restarted.FeedPolicy(); !verifiedPolicy.WFPVerified || verifiedPolicy.Pending {
		t.Fatalf("restart did not converge to verified blocking: %+v", verifiedPolicy)
	}
}

func TestEngineFeedPolicyWFPFailureReportsPendingNotSuccess(t *testing.T) {
	engine, protection, _ := newFeedPolicyEngine(t, true)
	ctx := context.Background()
	pending, err := engine.SetFeedActions(ctx, []FeedActionUpdate{{FeedID: "cins_army", Action: "BLOCK"}}, "Operator promotes CINS Army while the firewall bridge is degraded")
	if err != nil {
		t.Fatalf("policy intent persistence failed: %v", err)
	}
	if pending.Pending != true || pending.WFPVerified || pending.EnforcementState != "DEGRADED" {
		t.Fatalf("failed WFP verification was reported as effective blocking: %+v", pending)
	}
	var promoted FeedPolicyEntry
	for _, feed := range pending.Feeds {
		if feed.FeedID == "cins_army" {
			promoted = feed
		}
	}
	if promoted.Enforcement != "PENDING_WFP_VERIFICATION" {
		t.Fatalf("pending blocking authority is not explicit: %+v", promoted)
	}
	if len(pending.Warnings) == 0 || pending.EnforcementError == "" {
		t.Fatalf("pending state lacks explicit reasons: %+v", pending)
	}
	records := feedPolicyRecordResults(t, engine.ledger)
	pendingRecorded := false
	for _, record := range records {
		if record == "change/pending-wfp-verification" {
			pendingRecorded = true
		}
	}
	if !pendingRecorded {
		t.Fatalf("pending enforcement was not evidenced: %v", records)
	}
	// The override is a persisted intent: a later verified apply converges.
	protection.fail = false
	if err := engine.applyThreatEnforcement(ctx, engine.feeds.Status()); err != nil {
		t.Fatalf("recovery enforcement failed: %v", err)
	}
	recovered := engine.FeedPolicy()
	if !recovered.WFPVerified || recovered.Pending {
		t.Fatalf("recovered verification is inconsistent: %+v", recovered)
	}
}

func TestEngineFeedPolicyDowngradeAndResetAreExplicit(t *testing.T) {
	engine, _, _ := newFeedPolicyEngine(t, false)
	ctx := context.Background()
	if err := engine.applyThreatEnforcement(ctx, engine.feeds.Status()); err != nil {
		t.Fatalf("initial enforcement verification failed: %v", err)
	}
	downgraded, err := engine.SetFeedActions(ctx, []FeedActionUpdate{{FeedID: "feodo", Action: "CORRELATE_ONLY"}}, "Operator downgrades Feodo to correlation only after false positives")
	if err != nil {
		t.Fatalf("downgrade rejected: %v", err)
	}
	if !downgraded.WFPVerified || downgraded.Pending || !downgraded.EnforcementChanged {
		t.Fatalf("downgrade enforcement state is wrong: %+v", downgraded)
	}
	var feodo FeedPolicyEntry
	for _, feed := range downgraded.Feeds {
		if feed.FeedID == "feodo" {
			feodo = feed
		}
	}
	if feodo.Blocking || feodo.Enforcement != "NOT_BLOCKING" || feodo.EnforcementImpact != "REMOVES_BLOCK" || feodo.ConfiguredAction != threatintel.ActionCorrelateOnly {
		t.Fatalf("downgraded feed projection is wrong: %+v", feodo)
	}
	match := engine.feeds.Lookup(mustFeedPolicyAddr(t, "45.155.205.7"))
	if match.Action == threatintel.ActionBlock {
		t.Fatalf("downgraded feed still contributes a blocking decision: %+v", match)
	}
	reset, err := engine.SetFeedActions(ctx, []FeedActionUpdate{{FeedID: "feodo", Action: "DEFAULT"}}, "Operator restores the catalog default authority for Feodo")
	if err != nil {
		t.Fatalf("reset rejected: %v", err)
	}
	for _, feed := range reset.Feeds {
		if feed.FeedID == "feodo" {
			if feed.ActionSource != "DEFAULT" || feed.ConfiguredAction != threatintel.ActionBlock || !feed.Blocking {
				t.Fatalf("reset did not restore catalog authority: %+v", feed)
			}
		}
	}
	if !reset.EnforcementChanged {
		t.Fatal("reset did not report the enforcement change back to blocking")
	}
}

func TestEngineFeedPolicyValidationRejectsWithoutSideEffects(t *testing.T) {
	engine, protection, _ := newFeedPolicyEngine(t, false)
	before := engine.FeedPolicy()
	shortReason := "short"
	cases := []struct {
		name    string
		ctx     context.Context
		updates []FeedActionUpdate
		reason  string
	}{
		{"nil-context", nil, []FeedActionUpdate{{FeedID: "cins_army", Action: "BLOCK"}}, "Operator promotes CINS Army"},
		{"no-updates", context.Background(), nil, "Operator promotes CINS Army"},
		{"unknown-feed", context.Background(), []FeedActionUpdate{{FeedID: "nope", Action: "BLOCK"}}, "Operator promotes CINS Army"},
		{"invalid-action", context.Background(), []FeedActionUpdate{{FeedID: "cins_army", Action: "BLOCK_ALL"}}, "Operator promotes CINS Army"},
		{"duplicate", context.Background(), []FeedActionUpdate{{FeedID: "cins_army", Action: "BLOCK"}, {FeedID: "cins_army", Action: "DEFAULT"}}, "Operator promotes CINS Army"},
		{"short-reason", context.Background(), []FeedActionUpdate{{FeedID: "cins_army", Action: "BLOCK"}}, shortReason},
		{"control-reason", context.Background(), []FeedActionUpdate{{FeedID: "cins_army", Action: "BLOCK"}}, "operator reason with control\x00character"},
		{"too-many", context.Background(), make([]FeedActionUpdate, 17), "Operator promotes CINS Army"},
	}
	for _, testCase := range cases {
		if _, err := engine.SetFeedActions(testCase.ctx, testCase.updates, testCase.reason); err == nil {
			t.Fatalf("invalid feed policy request %q was accepted", testCase.name)
		}
	}
	if protection.calls != 0 {
		t.Fatalf("invalid requests reached the WFP applier: %d", protection.calls)
	}
	after := engine.FeedPolicy()
	if after.StoreState != before.StoreState || after.EnforcementGeneration != before.EnforcementGeneration || after.EnforcementChanged != before.EnforcementChanged {
		t.Fatalf("invalid requests mutated feed policy state: %+v", after)
	}
	for _, feed := range after.Feeds {
		if feed.ActionSource != "DEFAULT" {
			t.Fatalf("invalid requests persisted an override: %+v", feed)
		}
	}
}

func TestEngineFeedPolicyUnavailableAndCapacity(t *testing.T) {
	var unavailable *Engine
	policy := unavailable.FeedPolicy()
	if policy.StoreState != "UNAVAILABLE" || len(policy.Warnings) == 0 {
		t.Fatalf("unavailable manager was not explicit: %+v", policy)
	}
	if _, err := unavailable.SetFeedActions(context.Background(), []FeedActionUpdate{{FeedID: "feodo", Action: "BLOCK"}}, "Operator promotes CINS Army"); err == nil {
		t.Fatal("nil engine accepted a feed policy change")
	}
	engine, _, _ := newFeedPolicyEngine(t, false)
	updates := make([]FeedActionUpdate, 0, maximumFeedPolicyUpdates+1)
	for index := 0; index <= maximumFeedPolicyUpdates; index++ {
		updates = append(updates, FeedActionUpdate{FeedID: "cins_army", Action: "BLOCK"})
	}
	if _, err := engine.SetFeedActions(context.Background(), updates, "Operator promotes CINS Army"); err == nil {
		t.Fatal("oversized feed policy request was accepted")
	}
}

func mustFeedPolicyAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	parsed, err := netip.ParseAddr(value)
	if err != nil {
		prefix, prefixErr := netip.ParsePrefix(value)
		if prefixErr != nil {
			t.Fatalf("invalid test address %q: %v", value, err)
		}
		return prefix.Addr()
	}
	return parsed
}
