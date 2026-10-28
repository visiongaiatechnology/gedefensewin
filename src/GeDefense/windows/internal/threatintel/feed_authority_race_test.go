// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeAuthorityKeyringKeys provisions a trust anchor with an arbitrary key ring
// (the production helper only supports a single key).
func writeAuthorityKeyringKeys(t *testing.T, root string, keys map[string]ed25519.PublicKey) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	keyring := feedAuthorityKeyring{SchemaVersion: feedAuthorityKeyringSchema, Keys: make([]feedAuthorityKey, 0, len(keys))}
	for keyID, publicKey := range keys {
		keyring.Keys = append(keyring.Keys, feedAuthorityKey{KeyID: keyID, PublicKeyBase64: base64.RawStdEncoding.EncodeToString(publicKey)})
	}
	raw, err := json.Marshal(keyring)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feedAuthorityKeyringPath(root), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestFeedAuthorityVerificationConcurrentWithTrustAnchorReload is the -race
// regression for the former verifyFeedAuthorityDocumentWithKeys anti-pattern:
// verification used to temporarily assign m.authorityKeys outside authorityMu
// (and cached-generation verification read the field without the lock), racing
// with loadFeedAuthority. Verification now consumes the key snapshot as a
// parameter, so concurrent trust-anchor reloads must be race free.
func TestFeedAuthorityVerificationConcurrentWithTrustAnchorReload(t *testing.T) {
	root := t.TempDir()
	const keyID = "race-feed-authority"
	publicKey, privateKey := testAuthorityKeypair(t, keyID)
	writeAuthorityKeyring(t, root, keyID, publicKey)
	source, ok := sourceByKey("feodo")
	if !ok {
		t.Fatal("feodo source is missing from the catalog")
	}
	indicators := []string{"45.155.205.0/24", "185.220.101.0/24"}
	sort.Strings(indicators)
	generated := time.Now().UTC().Add(-time.Minute)
	attestation := feedAuthorityTestAttestation(source, indicators, 7, generated.Add(24*time.Hour))
	document := signedFeedAuthorityDocument(t, keyID, privateKey, 42, generated, attestation)
	writeSignedFeedAuthorityDocument(t, root, document)
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	cached := &sourceSnapshot{
		SchemaVersion: SchemaVersion, Key: source.Key, GeneratedUTC: generated, Action: source.Action,
		GenerationSHA256: digestIndicators(source.Key, source.Action, indicators),
		Indicators:       indicators, Authority: document,
	}

	const iterations = 40
	var workers sync.WaitGroup
	accepted := make(chan struct{}, 512)
	failures := make(chan error, 512)
	runVerification := func(verify func() error) {
		defer workers.Done()
		for index := 0; index < iterations; index++ {
			if err := verify(); err != nil {
				failures <- err
				continue
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
		}
	}
	for round := 0; round < 4; round++ {
		workers.Add(3)
		go runVerification(func() error {
			_, err := manager.verifyFetchedAuthority(source, indicators, nil)
			return err
		})
		go runVerification(func() error {
			return manager.verifyCachedAuthority(cached)
		})
		go func() {
			defer workers.Done()
			for index := 0; index < iterations; index++ {
				manager.loadFeedAuthority()
			}
		}()
	}
	workers.Wait()
	close(accepted)
	close(failures)
	for err := range failures {
		t.Fatalf("concurrent verification failed while the trust anchor was reloaded: %v", err)
	}
	if len(accepted) == 0 {
		t.Fatal("no concurrent verification succeeded")
	}
}

// TestFeedAuthorityMultiKeyRingAcceptsAuthorizedSignerOnly proves that a
// multi-key ring still verifies only signatures from provisioned keys and fails
// closed for an unknown signer.
func TestFeedAuthorityMultiKeyRingAcceptsAuthorizedSignerOnly(t *testing.T) {
	root := t.TempDir()
	publicPrimary, _ := testAuthorityKeypair(t, "primary")
	publicSecondary, privateSecondary := testAuthorityKeypair(t, "secondary")
	_, privateUnknown := testAuthorityKeypair(t, "unknown")
	writeAuthorityKeyringKeys(t, root, map[string]ed25519.PublicKey{"primary": publicPrimary, "secondary": publicSecondary})
	source, ok := sourceByKey("feodo")
	if !ok {
		t.Fatal("feodo source is missing from the catalog")
	}
	indicators := []string{"45.155.205.0/24"}
	sort.Strings(indicators)
	generated := time.Now().UTC().Add(-time.Minute)
	attestation := feedAuthorityTestAttestation(source, indicators, 7, generated.Add(24*time.Hour))

	authorized := signedFeedAuthorityDocument(t, "secondary", privateSecondary, 11, generated, attestation)
	writeSignedFeedAuthorityDocument(t, root, authorized)
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.verifyFetchedAuthority(source, indicators, nil); err != nil {
		t.Fatalf("authorized secondary key was rejected: %v", err)
	}

	unknown := signedFeedAuthorityDocument(t, "unknown", privateUnknown, 12, generated.Add(time.Second), attestation)
	writeSignedFeedAuthorityDocument(t, root, unknown)
	if _, err := manager.verifyFetchedAuthority(source, indicators, nil); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("unknown signer was not rejected with a signature failure: %v", err)
	}
}
