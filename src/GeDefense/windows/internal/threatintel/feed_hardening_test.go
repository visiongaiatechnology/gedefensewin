// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func testAuthorityKeypair(t *testing.T, keyID string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func writeAuthorityKeyring(t *testing.T, root, keyID string, publicKey ed25519.PublicKey) {
	t.Helper()
	keysDir := filepath.Join(root, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyring := feedAuthorityKeyring{SchemaVersion: feedAuthorityKeyringSchema, Keys: []feedAuthorityKey{{
		KeyID: keyID, PublicKeyBase64: base64.RawStdEncoding.EncodeToString(publicKey),
	}}}
	raw, err := json.Marshal(keyring)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feedAuthorityKeyringPath(root), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func signedFeedAuthorityDocument(t *testing.T, keyID string, privateKey ed25519.PrivateKey, sequence uint64, generated time.Time, attestations ...FeedAuthorityAttestation) *feedAuthorityDocument {
	t.Helper()
	document := &feedAuthorityDocument{SchemaVersion: feedAuthoritySchemaVersion, Sequence: sequence, KeyID: keyID, GeneratedUTC: generated, Feeds: attestations}
	document.SignatureEd25519 = "00"
	document.SignatureEd25519 = hexEncode(ed25519.Sign(privateKey, feedAuthorityDocumentMessage(*document)))
	return document
}

func writeSignedFeedAuthorityDocument(t *testing.T, root string, document *feedAuthorityDocument) {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feedAuthorityDocPath(root), append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func hexEncode(value []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(value)*2)
	for _, character := range value {
		out = append(out, digits[character>>4], digits[character&0x0f])
	}
	return string(out)
}

func feedAuthorityTestAttestation(source Source, indicators []string, sequence uint64, validUntil time.Time) FeedAuthorityAttestation {
	canonical := append([]string(nil), indicators...)
	sort.Strings(canonical)
	return FeedAuthorityAttestation{
		FeedKey: source.Key, Sequence: sequence, Action: source.Action,
		ContentSHA256: digestIndicators(source.Key, source.Action, canonical), ValidUntilUTC: validUntil,
	}
}

func TestSignedFeedAuthorityVerificationAndRollbackRejection(t *testing.T) {
	root := t.TempDir()
	keyID := "test-feed-authority"
	publicKey, privateKey := testAuthorityKeypair(t, keyID)
	writeAuthorityKeyring(t, root, keyID, publicKey)
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := sourceByKey("feodo")
	indicators := []string{"45.155.205.0/24", "185.220.101.0/24"}
	sort.Strings(indicators)
	generated := time.Now().UTC().Add(-time.Minute)
	attestation := feedAuthorityTestAttestation(source, indicators, 7, generated.Add(24*time.Hour))
	document := signedFeedAuthorityDocument(t, keyID, privateKey, 42, generated, attestation)
	writeSignedFeedAuthorityDocument(t, root, document)
	if _, err := manager.verifyFetchedAuthority(source, indicators, nil); err != nil {
		t.Fatalf("valid signed generation rejected: %v", err)
	}
	// Content substitution must be rejected even when the signature is valid.
	if _, err := manager.verifyFetchedAuthority(source, []string{"1.1.1.0/24"}, nil); err == nil {
		t.Fatal("indicator digest substitution was accepted")
	}
	// Expired attestations must be rejected fail-closed.
	expired := signedFeedAuthorityDocument(t, keyID, privateKey, 43, time.Now().UTC().Add(-48*time.Hour),
		feedAuthorityTestAttestation(source, indicators, 8, time.Now().UTC().Add(-24*time.Hour)))
	writeSignedFeedAuthorityDocument(t, root, expired)
	if _, err := manager.verifyFetchedAuthority(source, indicators, nil); err == nil {
		t.Fatal("expired signed feed authority was accepted")
	}
	// Anti-rollback: an older signed document sequence must be rejected.
	manager.updateFeedAuthorityState(document)
	older := signedFeedAuthorityDocument(t, keyID, privateKey, 41, generated.Add(time.Minute),
		feedAuthorityTestAttestation(source, indicators, 6, generated.Add(48*time.Hour)))
	writeSignedFeedAuthorityDocument(t, root, older)
	if _, err := manager.verifyFetchedAuthority(source, indicators, nil); err == nil {
		t.Fatal("signed feed authority rollback was accepted")
	}
	// Tampered signature must be rejected.
	document.SignatureEd25519 = strings.Repeat("0", ed25519.SignatureSize*2)
	writeSignedFeedAuthorityDocument(t, root, document)
	if _, err := manager.verifyFetchedAuthority(source, indicators, nil); err == nil {
		t.Fatal("tampered feed authority signature was accepted")
	}
}

func TestUnconfiguredFeedAuthorityIsReportedNotFaked(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if status := manager.Status(); status.FeedAuthenticity != feedAuthenticityUnconfigured {
		t.Fatalf("feed authenticity=%q, want %q", status.FeedAuthenticity, feedAuthenticityUnconfigured)
	}
	source, _ := sourceByKey("feodo")
	if document, err := manager.verifyFetchedAuthority(source, []string{"45.155.205.0/24"}, nil); err != nil || document != nil {
		t.Fatalf("unconfigured verifier did not report legacy TLS-only mode: document=%v err=%v", document, err)
	}
}

func TestPresentButBrokenFeedAuthorityFailsClosed(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feedAuthorityKeyringPath(root), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(root)
	if err != nil {
		t.Fatalf("broken trust anchor bricked the manager: %v", err)
	}
	source, _ := sourceByKey("feodo")
	if _, err := manager.verifyFetchedAuthority(source, []string{"45.155.205.0/24"}, nil); err == nil {
		t.Fatal("broken provisioned trust anchor did not fail closed")
	}
	if status := manager.Status(); status.FeedAuthenticity != feedAuthenticityFailed {
		t.Fatalf("feed authenticity=%q, want %q", status.FeedAuthenticity, feedAuthenticityFailed)
	}
}

func writeCachedFeedSnapshot(t *testing.T, root string, source Source, generated time.Time, indicators []string, authority *feedAuthorityDocument) {
	t.Helper()
	canonical := append([]string(nil), indicators...)
	sort.Strings(canonical)
	snapshot := sourceSnapshot{
		SchemaVersion: SchemaVersion, Key: source.Key, GeneratedUTC: generated, Action: source.Action,
		Attribution:      Attribution{Name: source.Name, URL: source.URL},
		GenerationSHA256: digestIndicators(source.Key, source.Action, canonical),
		Indicators:       canonical, Authority: authority,
	}
	if err := writeSourceSnapshot(root, snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestCachedGenerationWithoutAuthorityIsRejectedWhenTrustAnchorExists(t *testing.T) {
	root := t.TempDir()
	keyID := "cached-authority"
	publicKey, privateKey := testAuthorityKeypair(t, keyID)
	writeAuthorityKeyring(t, root, keyID, publicKey)
	source, _ := sourceByKey("feodo")
	indicators := []string{"45.155.205.0/24"}
	generated := time.Now().UTC().Add(-time.Minute)
	// Unsigned legacy snapshot must not be applied once the trust anchor exists.
	writeCachedFeedSnapshot(t, root, source, generated, indicators, nil)
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	if status.BlockingIndicators != 0 || status.EnforcementGeneration != "" {
		t.Fatalf("unsigned cached generation produced enforcement: %+v", status)
	}
	for _, feed := range status.Feeds {
		if feed.Key == "feodo" && feed.State != "UNAVAILABLE" {
			t.Fatalf("unsigned cached generation state=%q, want UNAVAILABLE", feed.State)
		}
	}
	// Now a correctly signed cached generation must be accepted offline.
	attestation := feedAuthorityTestAttestation(source, indicators, 3, generated.Add(24*time.Hour))
	document := signedFeedAuthorityDocument(t, keyID, privateKey, 9, generated, attestation)
	writeCachedFeedSnapshot(t, root, source, generated, indicators, document)
	verified, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, feed := range verified.Status().Feeds {
		if feed.Key == "feodo" {
			found = true
			if feed.State != "CACHED" || !feed.AuthorityVerified || feed.AuthoritySequence != 3 {
				t.Fatalf("signed cached generation not accepted offline: %+v", feed)
			}
		}
	}
	if !found {
		t.Fatal("feodo feed state missing")
	}
}

func TestHardFeedTTLExpiresStaleCache(t *testing.T) {
	root := t.TempDir()
	stale := time.Now().UTC().Add(-25 * time.Hour)
	for _, key := range []string{"feodo", "spamhaus_drop_v4", "spamhaus_drop_v6", "firehol_l1"} {
		source, _ := sourceByKey(key)
		writeCachedFeedSnapshot(t, root, source, stale, []string{"45.155.205.0/24"}, nil)
	}
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	if status.BlockingIndicators != 0 || status.EnforcementGeneration != "" {
		t.Fatalf("stale cache still claimed blocking enforcement: %+v", status)
	}
	expired := false
	for _, feed := range status.Feeds {
		if feed.State == "EXPIRED" {
			expired = true
		}
	}
	if !expired {
		t.Fatal("no feed was reported EXPIRED after the hard freshness TTL")
	}
	if _, statErr := os.Stat(enforcementSnapshotPath(root)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("stale enforcement snapshot file was left in place: %v", statErr)
	}
}

func TestStatusReadTimeTTLWithdrawsAgingGeneration(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Fresh manager: inject an in-memory generation that has just aged past TTL
	// to prove the read-time guard, not only startup loading, is fail-closed.
	source, _ := sourceByKey("feodo")
	old := time.Now().UTC().Add(-49 * time.Hour)
	manager.snapshots[source.Key] = sourceSnapshot{SchemaVersion: SchemaVersion, Key: source.Key, GeneratedUTC: old, Action: source.Action, Indicators: []string{"45.155.205.0/24"}}
	manager.statusMu.Lock()
	for index := range manager.status.Feeds {
		if manager.status.Feeds[index].Key == source.Key {
			manager.status.Feeds[index].LastSuccessUTC = old
			manager.status.Feeds[index].Indicators = 1
			manager.status.Feeds[index].EffectiveAction = ActionBlock
		}
	}
	manager.statusMu.Unlock()
	status := manager.Status()
	if status.BlockingIndicators != 0 || status.EnforcementGeneration != "" {
		t.Fatalf("aged generation still claimed blocking enforcement: %+v", status)
	}
	if !strings.Contains(status.Error, "freshness TTL") {
		t.Fatalf("read-time TTL withdrawal not surfaced: %q", status.Error)
	}
}

func TestClockRollbackWithdrawsFeedTrustAndRefusesSync(t *testing.T) {
	root := t.TempDir()
	if err := atomicWrite(feedClockPath(root), []byte(`{"schemaVersion":1,"highWaterUtc":"`+time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339Nano)+`"}`+"\n")); err != nil {
		t.Fatal(err)
	}
	source, _ := sourceByKey("feodo")
	writeCachedFeedSnapshot(t, root, source, time.Now().UTC(), []string{"45.155.205.0/24"}, nil)
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	if !status.FeedClockRollback || status.BlockingIndicators != 0 {
		t.Fatalf("clock rollback did not withdraw feed trust: %+v", status)
	}
	if err := manager.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "wall-clock rollback") {
		t.Fatalf("sync did not refuse to run on a rolled-back clock: %v", err)
	}
}

func TestFeedPolicyStoreIsAuthenticated(t *testing.T) {
	manager, root := newFeedPolicyTestManager(t)
	correlate := ActionCorrelateOnly
	if _, err := manager.SetFeedActions([]FeedActionChange{{FeedKey: "feodo", Action: &correlate}}, feedPolicyTestDigest(), time.Now().UTC()); err != nil {
		t.Fatalf("set feed action: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, feedPolicyFileName))
	if err != nil {
		t.Fatal(err)
	}
	var state feedPolicyState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.MAC) != 64 {
		t.Fatalf("feed policy store is not authenticated: mac=%q", state.MAC)
	}
	// Tamper the persisted authority while keeping the old MAC.
	state.Overrides = append(state.Overrides, FeedPolicyOverride{FeedKey: "cins_army", Action: ActionBlock, UpdatedUTC: time.Now().UTC()})
	tampered, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, feedPolicyFileName), append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(root)
	if err != nil {
		t.Fatalf("tampered feed policy store bricked startup: %v", err)
	}
	policy := restarted.FeedPolicy()
	if policy.StoreState == feedPolicySourcePersisted {
		t.Fatalf("tampered feed policy store was accepted: %+v", policy)
	}
	if !strings.Contains(policy.StoreError, "authentication") {
		t.Fatalf("tampered feed policy store error is not explicit: %q", policy.StoreError)
	}
	// Catalog defaults stay effective: a silent BLOCK downgrade is impossible.
	for _, entry := range policy.Entries {
		if entry.FeedKey == "feodo" && entry.EffectiveAction != ActionBlock {
			t.Fatalf("tampered store changed the effective authority: %+v", entry)
		}
	}
}
