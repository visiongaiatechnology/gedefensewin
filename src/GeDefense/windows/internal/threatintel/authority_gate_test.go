// STATUS: PLATIN VGT SUPREME
package threatintel

// FIND-WIN-015 regression tests: the signed feed-authority gate is fail-closed,
// and the immutable catalog action ceiling is enforced centrally (model +
// compiler), not only in the UI/API layer.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSignedAuthorityEnablesBlockingEnforcement proves the positive path: a
// verified key ring plus a signed cached generation still produces blocking
// enforcement (the fix must not simply disable threat intelligence).
func TestSignedAuthorityEnablesBlockingEnforcement(t *testing.T) {
	root := t.TempDir()
	const keyID = "authority-gate-key"
	publicKey, privateKey := testAuthorityKeypair(t, keyID)
	writeAuthorityKeyring(t, root, keyID, publicKey)
	source, _ := sourceByKey("feodo")
	indicators := []string{"45.155.205.0/24"}
	generated := time.Now().UTC().Add(-time.Minute)
	attestation := feedAuthorityTestAttestation(source, indicators, 3, generated.Add(24*time.Hour))
	document := signedFeedAuthorityDocument(t, keyID, privateKey, 8, generated, attestation)
	writeSignedFeedAuthorityDocument(t, root, document)
	writeCachedFeedSnapshot(t, root, source, generated, indicators, document)
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	if status.FeedAuthenticity != feedAuthenticityEnforced || status.FeedEnforcement != feedEnforcementVerified {
		t.Fatalf("verified authority was not projected: %+v", status)
	}
	if status.BlockingIndicators <= 0 || len(status.EnforcementGeneration) != 64 {
		t.Fatalf("verified signed generation produced no enforcement: %+v", status)
	}
	for _, feed := range status.Feeds {
		if feed.Key == "feodo" {
			if feed.EffectiveAction != ActionBlock || !feed.AuthorityVerified {
				t.Fatalf("verified feodo feed lost enforcement authority: %+v", feed)
			}
		}
	}
	match := manager.Lookup(mustFeedPolicyAddr(t, "45.155.205.7"))
	if !match.Found || match.Action != ActionBlock {
		t.Fatalf("verified signed generation did not reach the lookup index: %+v", match)
	}
}

// TestUnverifiedAuthorityCannotReachCompiler proves the gate is enforced before
// the compiler even when valid indicators are present in memory.
func TestUnverifiedAuthorityCannotReachCompiler(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, _ := sourceByKey("feodo")
	manager.snapshots[source.Key] = sourceSnapshot{
		SchemaVersion: SchemaVersion, Key: source.Key, GeneratedUTC: time.Now().UTC(),
		Action: source.Action, Indicators: []string{"45.155.205.0/24"},
	}
	if action := manager.effectiveAction(source.Key); action != ActionAnnotateOnly {
		t.Fatalf("unverified authority resolved to %q, want ANNOTATE_ONLY", action)
	}
	index := buildIndex(manager.applyEffectiveActions(manager.snapshots))
	if index.blocking != 0 || len(index.blockIndicators) != 0 {
		t.Fatalf("unverified authority reached the enforcement compiler: blocking=%d %v", index.blocking, index.blockIndicators)
	}
	if index.annotation == 0 {
		t.Fatalf("unverified data was not retained for display/audit: %+v", index)
	}
}

// TestAnnotateOnlyPromotionRejectedBySetFeedActions proves the operator API
// refuses to escalate an ANNOTATE_ONLY feed.
func TestAnnotateOnlyPromotionRejectedBySetFeedActions(t *testing.T) {
	manager, _ := newFeedPolicyTestManager(t)
	before := manager.FeedPolicy()
	block := ActionBlock
	_, err := manager.SetFeedActions([]FeedActionChange{{FeedKey: "tor_exit", Action: &block}}, feedPolicyTestDigest(), time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "ANNOTATE_ONLY") {
		t.Fatalf("ANNOTATE_ONLY promotion was not rejected explicitly: %v", err)
	}
	after := manager.FeedPolicy()
	if after.EnforcementGeneration != before.EnforcementGeneration || after.StoreState != before.StoreState {
		t.Fatalf("rejected promotion mutated policy state: %+v", after)
	}
	if entry := feedPolicyEntry(t, after, "tor_exit"); entry.EffectiveAction != ActionAnnotateOnly || entry.Blocking {
		t.Fatalf("rejected promotion changed the effective authority: %+v", entry)
	}
}

// TestAnnotateOnlyCeilingEnforcedCentrally proves that even an already escalated
// snapshot (a legacy/tampered caller that bypasses SetFeedActions) cannot enter
// the compiler or the status projection as BLOCK.
func TestAnnotateOnlyCeilingEnforcedCentrally(t *testing.T) {
	escalated := map[string]sourceSnapshot{
		"tor_exit": {
			SchemaVersion: SchemaVersion, Key: "tor_exit", GeneratedUTC: time.Now().UTC(),
			Action: ActionBlock, Indicators: []string{"50.155.205.0/24"},
		},
	}
	capped := applyEffectiveActionsToSnapshots(escalated, map[string]FeedPolicyOverride{
		"tor_exit": {FeedKey: "tor_exit", Action: ActionBlock, UpdatedUTC: time.Now().UTC()},
	}, true)
	if capped["tor_exit"].Action != ActionAnnotateOnly {
		t.Fatalf("override escalated an ANNOTATE_ONLY feed: %q", capped["tor_exit"].Action)
	}
	index := buildIndex(escalated)
	if index.blocking != 0 || len(index.blockIndicators) != 0 {
		t.Fatalf("escalated ANNOTATE_ONLY snapshot reached enforcement: %+v", index.blockIndicators)
	}
	if index.annotation != 1 {
		t.Fatalf("ANNOTATE_ONLY indicator was not kept for display: %+v", index)
	}
}

// TestPersistedAnnotateOnlyEscalationIsClamped proves a legacy/tampered override
// store that contains an ANNOTATE_ONLY promotion cannot take effect even when the
// store MAC is valid (for example an older release wrote it).
func TestPersistedAnnotateOnlyEscalationIsClamped(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	escalated := map[string]FeedPolicyOverride{
		"tor_exit": {FeedKey: "tor_exit", Action: ActionBlock, UpdatedUTC: time.Now().UTC()},
	}
	payload, err := marshalFeedPolicyState(escalated, time.Now().UTC(), manager.feedPolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(feedPolicyPath(root), payload); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(root)
	if err != nil {
		t.Fatalf("persisted escalation bricked startup: %v", err)
	}
	if action := restarted.effectiveAction("tor_exit"); action != ActionAnnotateOnly {
		t.Fatalf("persisted ANNOTATE_ONLY escalation took effect: %q", action)
	}
	policy := restarted.FeedPolicy()
	entry := feedPolicyEntry(t, policy, "tor_exit")
	if entry.ConfiguredAction != ActionBlock || entry.EffectiveAction != ActionAnnotateOnly || entry.Blocking {
		t.Fatalf("persisted escalation projection is wrong: %+v", entry)
	}
	if policy.BlockingIndicators != 0 {
		t.Fatalf("persisted escalation fabricated blocking indicators: %+v", policy)
	}
}

// TestEnforcementSnapshotWithdrawnWhenAuthorityDisappears proves that a restart
// without the trust anchor removes a previously written enforcement projection
// instead of leaving stale blocking data on disk.
func TestEnforcementSnapshotWithdrawnWhenAuthorityDisappears(t *testing.T) {
	root := t.TempDir()
	const keyID = "withdraw-authority-key"
	publicKey, privateKey := testAuthorityKeypair(t, keyID)
	writeAuthorityKeyring(t, root, keyID, publicKey)
	source, _ := sourceByKey("feodo")
	indicators := []string{"45.155.205.0/24"}
	generated := time.Now().UTC().Add(-time.Minute)
	attestation := feedAuthorityTestAttestation(source, indicators, 3, generated.Add(24*time.Hour))
	document := signedFeedAuthorityDocument(t, keyID, privateKey, 8, generated, attestation)
	writeSignedFeedAuthorityDocument(t, root, document)
	writeCachedFeedSnapshot(t, root, source, generated, indicators, document)
	if _, err := NewManager(root); err != nil {
		t.Fatal(err)
	}
	// Simulate a trust-anchor deletion/rollback.
	if err := os.Remove(feedAuthorityKeyringPath(root)); err != nil {
		t.Fatal(err)
	}
	withdrawn, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	status := withdrawn.Status()
	if status.FeedAuthenticity != feedAuthenticityUnverified || status.BlockingIndicators != 0 || status.EnforcementGeneration != "" {
		t.Fatalf("missing authority did not withdraw enforcement: %+v", status)
	}
	if _, statErr := os.Stat(filepath.Join(root, "threat-intelligence-enforcement.json")); !os.IsNotExist(statErr) {
		t.Fatalf("enforcement projection survived the authority loss: %v", statErr)
	}
}

func TestHostFeedAuthorityProvisionsAndAttestsLegacyCachedSnapshots(t *testing.T) {
	root := t.TempDir()
	generated := time.Now().UTC().Add(-time.Minute)
	fixtures := map[string][]string{
		"feodo":            {"45.155.205.0/24"},
		"spamhaus_drop_v4": {"46.155.205.0/24"},
		"spamhaus_drop_v6": {"2a02:1234::/32"},
		"firehol_l1":       {"47.155.205.0/24"},
	}
	for key, indicators := range fixtures {
		source, _ := sourceByKey(key)
		writeCachedFeedSnapshot(t, root, source, generated, indicators, nil)
	}
	if err := EnsureHostFeedAuthority(root); err != nil {
		t.Fatalf("EnsureHostFeedAuthority() failed: %v", err)
	}
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	status := manager.Status()
	if status.FeedAuthenticity != feedAuthenticityEnforced || status.FeedEnforcement != feedEnforcementVerified {
		t.Fatalf("host feed authority was not enforced: %+v", status)
	}
	if status.State != "CACHED" || status.BlockingIndicators != 4 || status.BlockingFeedsReady != 4 || status.BlockingFeedsTotal != 4 || len(status.EnforcementGeneration) != 64 {
		t.Fatalf("host feed authority did not attest cached blocking feeds: %+v", status)
	}
	if _, statErr := os.Stat(feedAuthorityDocPath(root)); statErr != nil {
		t.Fatalf("feed-authority.json was not written: %v", statErr)
	}
	if _, statErr := os.Stat(enforcementSnapshotPath(root)); statErr != nil {
		t.Fatalf("threat-intelligence-enforcement.json was not written: %v", statErr)
	}
}

func TestExternalKeyringOverridesHostFeedAuthority(t *testing.T) {
	root := t.TempDir()
	if err := EnsureHostFeedAuthority(root); err != nil {
		t.Fatalf("EnsureHostFeedAuthority() failed: %v", err)
	}
	extPub, _ := testAuthorityKeypair(t, "external-enterprise-key")
	writeAuthorityKeyring(t, root, "external-enterprise-key", extPub)
	source, _ := sourceByKey("feodo")
	writeCachedFeedSnapshot(t, root, source, time.Now().UTC().Add(-time.Minute), []string{"45.155.205.0/24"}, nil)
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}
	status := manager.Status()
	if status.BlockingIndicators != 0 || status.EnforcementGeneration != "" {
		t.Fatalf("local host authority signed despite external pinned keyring: %+v", status)
	}
}
