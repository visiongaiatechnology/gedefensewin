// STATUS: PLATIN VGT SUPREME
package mhx

// FIND-WIN-015 test fixture: the threat-intelligence enforcement gate is
// fail-closed, so a cached feed generation only becomes a blocking/enforcement
// basis when it carries a valid Ed25519 feed-authority attestation from a
// provisioned trust anchor. These helpers provision that anchor and one signed
// authority document for the offline test fixtures, exactly like the release
// pipeline does.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

const mhxTestFeedAuthorityKeyID = "mhx-test-feed-authority"

// provisionSignedFeedAuthority writes a public-key ring, one signed authority
// document covering indicatorsByFeed and returns the document as a generic map
// ready to be embedded into a cached source snapshot ("authority" field).
func provisionSignedFeedAuthority(t *testing.T, intelRoot string, generated time.Time, indicatorsByFeed map[string][]string) any {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate feed authority key: %v", err)
	}
	keysDirectory := filepath.Join(intelRoot, "keys")
	if err := os.MkdirAll(keysDirectory, 0o700); err != nil {
		t.Fatalf("create feed authority key directory: %v", err)
	}
	keyring := map[string]any{
		"schemaVersion": 1,
		"keys": []map[string]any{{
			"keyId":           mhxTestFeedAuthorityKeyID,
			"publicKeyBase64": base64.RawStdEncoding.EncodeToString(publicKey),
		}},
	}
	keyringRaw, err := json.Marshal(keyring)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDirectory, "feed-authority.pubkeys.json"), keyringRaw, 0o600); err != nil {
		t.Fatalf("write feed authority key ring: %v", err)
	}

	attestations := make([]threatintel.FeedAuthorityAttestation, 0, len(indicatorsByFeed))
	for feedKey, indicators := range indicatorsByFeed {
		var source threatintel.Source
		found := false
		for _, candidate := range threatintel.Catalog() {
			if candidate.Key == feedKey {
				source, found = candidate, true
				break
			}
		}
		if !found {
			t.Fatalf("feed %q is missing from the catalog", feedKey)
		}
		sorted := append([]string(nil), indicators...)
		sort.Strings(sorted)
		digest := sha256.Sum256([]byte(feedKey + "\n" + string(source.Action) + "\n" + strings.Join(sorted, "\n")))
		attestations = append(attestations, threatintel.FeedAuthorityAttestation{
			FeedKey: feedKey, Sequence: 5, ContentSHA256: hex.EncodeToString(digest[:]),
			Action: source.Action, ValidUntilUTC: generated.Add(24 * time.Hour),
		})
	}
	sort.Slice(attestations, func(left, right int) bool { return attestations[left].FeedKey < attestations[right].FeedKey })

	// The signed canonical message is identical to threatintel.feedAuthorityMessage.
	message := struct {
		SchemaVersion int                                    `json:"schemaVersion"`
		Sequence      uint64                                 `json:"sequence"`
		KeyID         string                                 `json:"keyId"`
		GeneratedUTC  string                                 `json:"generatedUtc"`
		Feeds         []threatintel.FeedAuthorityAttestation `json:"feeds"`
	}{
		SchemaVersion: 1,
		Sequence:      5,
		KeyID:         mhxTestFeedAuthorityKeyID,
		GeneratedUTC:  generated.UTC().Format(time.RFC3339Nano),
		Feeds:         attestations,
	}
	messageRaw, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, messageRaw)
	document := map[string]any{
		"schemaVersion":    1,
		"sequence":         5,
		"keyId":            mhxTestFeedAuthorityKeyID,
		"generatedUtc":     generated.UTC().Format(time.RFC3339Nano),
		"feeds":            attestations,
		"signatureEd25519": hex.EncodeToString(signature),
	}
	documentRaw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(intelRoot, "feed-authority.json"), append(documentRaw, '\n'), 0o600); err != nil {
		t.Fatalf("write signed feed authority document: %v", err)
	}
	return document
}
