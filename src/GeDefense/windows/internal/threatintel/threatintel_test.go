// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"bytes"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCatalogActionsAreFailSafe(t *testing.T) {
	expected := map[string]Action{
		"feodo":            ActionBlock,
		"spamhaus_drop_v4": ActionBlock,
		"spamhaus_drop_v6": ActionBlock,
		"cins_army":        ActionCorrelateOnly,
		"blocklist_de":     ActionCorrelateOnly,
		"emerging_threats": ActionCorrelateOnly,
		"ipsum":            ActionCorrelateOnly,
		"firehol_l1":       ActionCorrelateOnly,
		"tor_exit":         ActionAnnotateOnly,
	}
	if len(catalog) != len(expected) {
		t.Fatalf("expected %d feeds, got %d", len(expected), len(catalog))
	}
	for _, source := range catalog {
		if expected[source.Key] != source.Action {
			t.Fatalf("unsafe action mapping for %s: %s", source.Key, source.Action)
		}
	}
}

func TestThreatTokenHardening(t *testing.T) {
	for _, value := range []string{"' OR 1=1--", "1.2.3.4;DROP", "1.2.3.4\n8.8.8.8", "0.0.0.0/0", "10.0.0.1", "168.63.129.16", "2001:db8::/32"} {
		if _, err := parseThreatToken(value); err == nil {
			t.Fatalf("unsafe threat token accepted: %q", value)
		}
	}
	for _, value := range []string{"1.1.1.1", "8.8.8.0/24", "2606:4700:4700::1111", "2606:4700::/32"} {
		if _, err := parseThreatToken(value); err != nil {
			t.Fatalf("valid threat token rejected: %q: %v", value, err)
		}
	}
}

func TestPlainParsersHandleIPsumAndComments(t *testing.T) {
	body := []byte("# comment\n1.1.1.1\t4\n8.8.8.0/24 ; note\nheader text\n")
	prefixes, err := parsePlain(body)
	if err != nil || len(prefixes) != 2 {
		t.Fatalf("plain parser failed: %v %#v", err, prefixes)
	}
}

func TestSpamhausMetadataIsMandatory(t *testing.T) {
	source, _ := sourceByKey("spamhaus_drop_v4")
	if _, _, err := parseSource(source, []byte("{\"cidr\":\"93.184.216.0/24\"}\n")); err == nil {
		t.Fatal("Spamhaus snapshot without attribution metadata was accepted")
	}
	body := []byte("{\"cidr\":\"93.184.216.0/24\"}\n{\"type\":\"metadata\",\"timestamp\":1787822042,\"copyright\":\"Spamhaus\",\"terms\":\"https://www.spamhaus.org/drop/terms/\"}\n")
	prefixes, attribution, err := parseSource(source, body)
	if err != nil || len(prefixes) != 1 || attribution.SourceTimestampUnix != 1787822042 {
		t.Fatalf("valid Spamhaus snapshot rejected: %v %+v", err, attribution)
	}
}

func TestIndexPreservesSourcesAndHighestAction(t *testing.T) {
	now := time.Now().UTC()
	snapshots := map[string]sourceSnapshot{
		"tor_exit":  {Key: "tor_exit", GeneratedUTC: now, Action: ActionAnnotateOnly, Indicators: []string{"1.1.1.1/32"}},
		"cins_army": {Key: "cins_army", GeneratedUTC: now, Action: ActionCorrelateOnly, Indicators: []string{"1.1.1.0/24"}},
		"feodo":     {Key: "feodo", GeneratedUTC: now, Action: ActionBlock, Indicators: []string{"1.1.1.1/32"}},
	}
	index := buildIndex(snapshots)
	match := index.Lookup(netip.MustParseAddr("1.1.1.1"))
	if !match.Found || match.Action != ActionBlock || len(match.Sources) != 3 {
		t.Fatalf("action/source merge failed: %+v", match)
	}
	if index.blocking != 1 || index.correlation != 1 || index.annotation != 0 {
		t.Fatalf("unexpected effective index counts: block=%d correlate=%d annotate=%d", index.blocking, index.correlation, index.annotation)
	}
}

func TestAnnotateOnlyNeverEntersEnforcementSnapshot(t *testing.T) {
	now := time.Now().UTC()
	index := buildIndex(map[string]sourceSnapshot{
		"tor_exit": {Key: "tor_exit", GeneratedUTC: now, Action: ActionAnnotateOnly, Indicators: []string{"1.1.1.1/32"}},
		"feodo":    {Key: "feodo", GeneratedUTC: now, Action: ActionBlock, Indicators: []string{"8.8.8.8/32"}},
	})
	if len(index.blockIndicators) != 1 || index.blockIndicators[0] != "8.8.8.8/32" {
		t.Fatalf("annotate-only indicator leaked into enforcement: %#v", index.blockIndicators)
	}
}

func TestSuspiciousShrinkGate(t *testing.T) {
	if !suspiciousShrink(10000, 500) {
		t.Fatal("90%+ feed collapse was not rejected")
	}
	if suspiciousShrink(10000, 1500) {
		t.Fatal("non-catastrophic feed shrink was rejected")
	}
	if suspiciousShrink(50, 1) {
		t.Fatal("small feed shrink should not trigger ratio gate")
	}
}

func TestEnforcementCompilerSubtractsProtectedHostWithoutDroppingWholeSubnet(t *testing.T) {
	compiled, err := compileEnforcementIndicators([]string{"8.8.8.0/24"}, []netip.Prefix{netip.MustParsePrefix("8.8.8.42/32")})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 8 {
		t.Fatalf("expected minimal /24-minus-/32 complement of 8 prefixes, got %d: %#v", len(compiled), compiled)
	}
	for _, value := range compiled {
		prefix := netip.MustParsePrefix(value)
		if prefix.Contains(netip.MustParseAddr("8.8.8.42")) {
			t.Fatalf("protected management host leaked into enforcement: %s", value)
		}
	}
	for _, address := range []string{"8.8.8.41", "8.8.8.43", "8.8.8.200"} {
		candidate := netip.MustParseAddr(address)
		found := false
		for _, value := range compiled {
			if netip.MustParsePrefix(value).Contains(candidate) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("non-protected address %s was accidentally removed", address)
		}
	}
}

func TestEnforcementCompilerSubtractsProtectedSubnetAndCompacts(t *testing.T) {
	compiled, err := compileEnforcementIndicators(
		[]string{"8.8.8.0/25", "8.8.8.128/25", "8.8.8.64/26"},
		[]netip.Prefix{netip.MustParsePrefix("8.8.8.64/26")},
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"8.8.8.0/26", "8.8.8.128/25"}
	if len(compiled) != len(expected) {
		t.Fatalf("unexpected compiled prefix count: %#v", compiled)
	}
	for index := range expected {
		if compiled[index] != expected[index] {
			t.Fatalf("unexpected compiler output at %d: got %s want %s", index, compiled[index], expected[index])
		}
	}
}

func TestProtectedNetworkPolicyRejectsBroadAndReservedExceptions(t *testing.T) {
	for _, value := range []string{"0.0.0.0/0", "8.0.0.0/8", "10.0.0.0/24", "203.0.113.1/32", "::/0", "2606::/16"} {
		if _, err := parseProtectedPrefix(value); err == nil {
			t.Fatalf("unsafe protected prefix accepted: %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "8.8.8.0/24", "2606:4700:4700::1111", "2606:4700:4700::/48"} {
		if _, err := parseProtectedPrefix(value); err != nil {
			t.Fatalf("valid protected prefix rejected: %s: %v", value, err)
		}
	}
}

func TestProtectedNetworkPolicyAuthenticationDetectsTampering(t *testing.T) {
	root := t.TempDir()
	key, err := loadOrCreateProtectedPolicyKey(root)
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")}
	policy, err := writeProtectedPolicy(root, key, prefixes, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	loaded, _, err := loadProtectedPolicy(root, key)
	if err != nil || loaded.GenerationSHA256 != policy.GenerationSHA256 {
		t.Fatalf("authenticated policy reload failed: %v", err)
	}
	path := protectedPolicyPath(root)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte("8.8.8.8/32"), []byte("9.9.9.9/32"), 1)
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadProtectedPolicy(root, key); err == nil {
		t.Fatal("tampered protected network policy was accepted")
	}
}

func TestLookupMarksProtectedNetworkWithoutLosingThreatAttribution(t *testing.T) {
	now := time.Now().UTC()
	index := buildIndex(map[string]sourceSnapshot{
		"feodo": {Key: "feodo", GeneratedUTC: now, Action: ActionBlock, Indicators: []string{"8.8.8.0/24"}},
	})
	manager := &Manager{protectedTrie: buildPrefixTrie([]netip.Prefix{netip.MustParsePrefix("8.8.8.42/32")})}
	manager.index.Store(index)
	match := manager.Lookup(netip.MustParseAddr("8.8.8.42"))
	if !match.Found || !match.Protected || match.Action != ActionBlock || len(match.Sources) != 1 || match.Sources[0] != "feodo" {
		t.Fatalf("protected lookup lost threat context: %+v", match)
	}
	outside := manager.Lookup(netip.MustParseAddr("8.8.8.43"))
	if !outside.Found || outside.Protected {
		t.Fatalf("non-protected neighbor misclassified: %+v", outside)
	}
}

func TestEnforcementSnapshotRejectsMismatchedProtectionGeneration(t *testing.T) {
	index := buildIndex(map[string]sourceSnapshot{
		"feodo": {Key: "feodo", GeneratedUTC: time.Now().UTC(), Action: ActionBlock, Indicators: []string{"8.8.8.8/32"}},
	})
	policy := protectedPolicyFromStrings([]string{"9.9.9.9/32"}, time.Now().UTC())
	policy.GenerationSHA256 = strings.Repeat("0", 64)
	if err := writeEnforcementSnapshot(t.TempDir(), time.Now().UTC(), index, 1, policy); err == nil {
		t.Fatal("enforcement snapshot accepted mismatched protected-network generation")
	}
}

func TestProtectedPolicyRollbackRestoresPreviousAuthenticatedGeneration(t *testing.T) {
	root := t.TempDir()
	key, err := loadOrCreateProtectedPolicyKey(root)
	if err != nil {
		t.Fatal(err)
	}
	oldPrefixes := []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")}
	oldPolicy, err := writeProtectedPolicy(root, key, oldPrefixes, time.Now().UTC().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeProtectedPolicy(root, key, []netip.Prefix{netip.MustParsePrefix("9.9.9.9/32")}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := restoreProtectedPolicy(root, key, oldPolicy, oldPrefixes); err != nil {
		t.Fatal(err)
	}
	restored, _, err := loadProtectedPolicy(root, key)
	if err != nil {
		t.Fatal(err)
	}
	if !fixedHexEqual(restored.GenerationSHA256, oldPolicy.GenerationSHA256) || len(restored.Prefixes) != 1 || restored.Prefixes[0] != "8.8.8.8/32" {
		t.Fatalf("protected policy rollback mismatch: %+v", restored)
	}
}
