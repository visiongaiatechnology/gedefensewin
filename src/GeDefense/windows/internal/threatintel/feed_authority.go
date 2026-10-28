// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Signed feed authority (DP-FIND-002)
//
// The upstream feeds are TXT/NDJSON documents without a cryptographic
// signature. GeDefense therefore verifies a detached, Ed25519-signed authority
// document that binds, for every feed:
//
//   - the canonical indicator-list digest (the same digest stored as
//     sourceSnapshot.GenerationSHA256),
//   - the catalog authority (BLOCK/CORRELATE_ONLY/ANNOTATE_ONLY),
//   - a monotonically increasing sequence number (anti-rollback),
//   - a hard validity window (validUntilUtc).
//
// Provisioning requirement (exact, no signing key is shipped in this repo):
//
//  1. The release/operations pipeline generates an Ed25519 key pair externally.
//     Only the public key is provisioned on the host.
//  2. The public key ring is written to
//     %ProgramData%\VGT\GeDefense\mhx\intelligence\keys\feed-authority.pubkeys.json
//     with schema {"schemaVersion":1,"keys":[{"keyId":"...","publicKeyBase64":"..."}]}.
//     The file is not secret, but it is a trust anchor: it must be written only
//     by the installer/administrator, never by the service's feed loop.
//  3. For every published generation the pipeline writes a signed document to
//     %ProgramData%\VGT\GeDefense\mhx\intelligence\feed-authority.json with the
//     schema below. The signature covers the canonical message defined by
//     feedAuthorityDocumentMessage (feeds sorted by feedKey, RFC3339Nano times).
//  4. When the public key ring exists, every fetched feed and every cached
//     generation MUST carry a valid attestation. Missing/invalid/expired/
//     rolled-back attestations are rejected fail-closed. Without a key ring the
//     manager reports FeedAuthenticity=UNCONFIGURED and the hard TTL still
//     expires every unverified generation (DP-FIND-003).
const (
	feedAuthoritySchemaVersion      = 1
	feedAuthorityDocFileName        = "feed-authority.json"
	feedAuthorityKeyringFileName    = "feed-authority.pubkeys.json"
	feedAuthorityStateFileName      = "feed-authority.state.json"
	feedAuthorityKeyringSchema      = 1
	maximumFeedAuthorityDocBytes    = 256 << 10
	maximumFeedAuthorityKeyring     = 64 << 10
	maximumFeedAuthorityValidity    = 30 * 24 * time.Hour
	feedAuthorityFutureTolerance    = 5 * time.Minute
	feedAuthenticityUnconfigured    = "UNCONFIGURED"
	feedAuthenticityEnforced        = "ENFORCED"
	feedAuthenticityFailed          = "FAILED"
	feedAuthorityStateSchemaVersion = 1
)

// FeedAuthorityAttestation binds one feed generation to a signed document.
type FeedAuthorityAttestation struct {
	FeedKey       string    `json:"feedKey"`
	Sequence      uint64    `json:"sequence"`
	ContentSHA256 string    `json:"contentSha256"`
	Action        Action    `json:"action"`
	ValidUntilUTC time.Time `json:"validUntilUtc"`
}

type feedAuthorityDocument struct {
	SchemaVersion    int                        `json:"schemaVersion"`
	Sequence         uint64                     `json:"sequence"`
	KeyID            string                     `json:"keyId"`
	GeneratedUTC     time.Time                  `json:"generatedUtc"`
	Feeds            []FeedAuthorityAttestation `json:"feeds"`
	SignatureEd25519 string                     `json:"signatureEd25519"`
}

type feedAuthorityMessage struct {
	SchemaVersion int                        `json:"schemaVersion"`
	Sequence      uint64                     `json:"sequence"`
	KeyID         string                     `json:"keyId"`
	GeneratedUTC  string                     `json:"generatedUtc"`
	Feeds         []FeedAuthorityAttestation `json:"feeds"`
}

type feedAuthorityKeyring struct {
	SchemaVersion int                `json:"schemaVersion"`
	Keys          []feedAuthorityKey `json:"keys"`
}

type feedAuthorityKey struct {
	KeyID           string `json:"keyId"`
	PublicKeyBase64 string `json:"publicKeyBase64"`
}

type feedAuthorityState struct {
	SchemaVersion    int       `json:"schemaVersion"`
	LastSequence     uint64    `json:"lastSequence"`
	LastGeneratedUTC time.Time `json:"lastGeneratedUtc"`
}

func feedAuthorityDocPath(root string) string {
	return filepath.Join(root, feedAuthorityDocFileName)
}

func feedAuthorityKeyringPath(root string) string {
	return filepath.Join(root, "keys", feedAuthorityKeyringFileName)
}

func feedAuthorityStatePath(root string) string {
	return filepath.Join(root, feedAuthorityStateFileName)
}

// loadFeedAuthorityKeyring loads the pinned Ed25519 public keys. configured is
// true whenever the trust-anchor file exists, even if it is invalid: a present
// but broken anchor must fail closed instead of silently disabling verification.
func loadFeedAuthorityKeyring(root string) (keys map[string]ed25519.PublicKey, configured bool, err error) {
	path := feedAuthorityKeyringPath(root)
	info, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		return nil, false, nil
	}
	if statErr != nil {
		return nil, true, statErr
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, true, errors.New("feed authority keyring must be a regular non-reparse file")
	}
	if info.Size() <= 0 || info.Size() > maximumFeedAuthorityKeyring {
		return nil, true, errors.New("feed authority keyring size rejected")
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, true, readErr
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var keyring feedAuthorityKeyring
	if decodeErr := decoder.Decode(&keyring); decodeErr != nil {
		return nil, true, errors.New("feed authority keyring JSON rejected")
	}
	if trailingErr := decoder.Decode(&struct{}{}); !errors.Is(trailingErr, io.EOF) {
		return nil, true, errors.New("feed authority keyring trailing data rejected")
	}
	if keyring.SchemaVersion != feedAuthorityKeyringSchema || len(keyring.Keys) == 0 || len(keyring.Keys) > 8 {
		return nil, true, errors.New("feed authority keyring metadata rejected")
	}
	keys = make(map[string]ed25519.PublicKey, len(keyring.Keys))
	for _, key := range keyring.Keys {
		if key.KeyID == "" || len(key.KeyID) > 32 || strings.ContainsAny(key.KeyID, "\r\n\x00") {
			return nil, true, errors.New("feed authority key identifier rejected")
		}
		publicKey, decodeErr := base64.RawStdEncoding.DecodeString(strings.TrimSpace(key.PublicKeyBase64))
		if decodeErr != nil {
			publicKey, decodeErr = base64.StdEncoding.DecodeString(strings.TrimSpace(key.PublicKeyBase64))
		}
		if decodeErr != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, true, errors.New("feed authority public key rejected")
		}
		if _, duplicate := keys[key.KeyID]; duplicate {
			return nil, true, errors.New("feed authority public key duplicated")
		}
		keys[key.KeyID] = ed25519.PublicKey(publicKey)
	}
	return keys, true, nil
}

func (m *Manager) loadFeedAuthority() {
	keys, configured, err := loadFeedAuthorityKeyring(m.root)
	m.authorityMu.Lock()
	defer m.authorityMu.Unlock()
	m.authorityKeys = keys
	m.authorityConfigured = configured
	if err != nil {
		m.authorityError = "feed authenticity trust anchor rejected: " + err.Error()
	} else {
		m.authorityError = ""
	}
	if !configured {
		m.authorityState = feedAuthorityState{}
		return
	}
	if state, stateErr := loadFeedAuthorityState(m.root); stateErr == nil {
		m.authorityState = state
	}
}

func loadFeedAuthorityState(root string) (feedAuthorityState, error) {
	raw, err := os.ReadFile(feedAuthorityStatePath(root))
	if errors.Is(err, os.ErrNotExist) {
		return feedAuthorityState{}, nil
	}
	if err != nil {
		return feedAuthorityState{}, err
	}
	if len(raw) == 0 || len(raw) > 8<<10 {
		return feedAuthorityState{}, errors.New("feed authority state size rejected")
	}
	var state feedAuthorityState
	if err := json.Unmarshal(raw, &state); err != nil || state.SchemaVersion != feedAuthorityStateSchemaVersion {
		return feedAuthorityState{}, errors.New("feed authority state rejected")
	}
	return state, nil
}

func (m *Manager) persistFeedAuthorityState(state feedAuthorityState) error {
	state.SchemaVersion = feedAuthorityStateSchemaVersion
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWrite(feedAuthorityStatePath(m.root), append(raw, '\n'))
}

func feedAuthorityDocumentMessage(document feedAuthorityDocument) []byte {
	feeds := append([]FeedAuthorityAttestation(nil), document.Feeds...)
	sort.Slice(feeds, func(left, right int) bool { return feeds[left].FeedKey < feeds[right].FeedKey })
	message := feedAuthorityMessage{
		SchemaVersion: document.SchemaVersion,
		Sequence:      document.Sequence,
		KeyID:         document.KeyID,
		GeneratedUTC:  document.GeneratedUTC.UTC().Format(time.RFC3339Nano),
		Feeds:         feeds,
	}
	raw, _ := json.Marshal(message)
	return raw
}

// verifyFeedAuthorityDocument verifies the detached Ed25519 signature against
// the supplied pinned public keys. keys MUST be a snapshot obtained under
// authorityMu (loadFeedAuthority replaces the map under a write lock and never
// mutates a published map); the verification itself therefore never touches
// Manager state and cannot race with a key-ring reload.
func (m *Manager) verifyFeedAuthorityDocument(document *feedAuthorityDocument, keys map[string]ed25519.PublicKey) error {
	if document == nil {
		return errors.New("signed feed authority document is missing")
	}
	if document.SchemaVersion != feedAuthoritySchemaVersion || document.Sequence == 0 ||
		len(document.Feeds) == 0 || len(document.Feeds) > len(catalog) ||
		document.GeneratedUTC.IsZero() || len(document.SignatureEd25519) != ed25519.SignatureSize*2 {
		return errors.New("signed feed authority document metadata rejected")
	}
	signature, err := hex.DecodeString(document.SignatureEd25519)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("signed feed authority signature encoding rejected")
	}
	for _, key := range keys {
		if ed25519.Verify(key, feedAuthorityDocumentMessage(*document), signature) {
			return nil
		}
	}
	return errors.New("signed feed authority signature invalid")
}

// verifyFetchedAuthority enforces verified-before-apply for a fetched feed. It
// returns the signed authority document to persist with the snapshot. Without a
// provisioned key ring it returns (nil, nil): the caller then records the
// generation as unverified and the hard TTL still bounds its lifetime.
func (m *Manager) verifyFetchedAuthority(source Source, indicators []string, previous *sourceSnapshot) (*feedAuthorityDocument, error) {
	m.authorityMu.RLock()
	configured := m.authorityConfigured
	authorityErr := m.authorityError
	keys := m.authorityKeys
	state := m.authorityState
	m.authorityMu.RUnlock()
	if !configured {
		return nil, nil
	}
	if authorityErr != "" {
		return nil, errors.New(authorityErr)
	}
	document, err := loadFeedAuthorityDocument(m.root)
	if err != nil {
		return nil, err
	}
	if err := m.verifyFeedAuthorityDocument(document, keys); err != nil {
		return nil, err
	}
	if document.Sequence < state.LastSequence {
		return nil, errors.New("signed feed authority rollback rejected")
	}
	if !state.LastGeneratedUTC.IsZero() && document.GeneratedUTC.Add(feedClockTolerance).Before(state.LastGeneratedUTC) {
		return nil, errors.New("signed feed authority generation rollback rejected")
	}
	now := m.effectiveNowUTC()
	if document.GeneratedUTC.After(now.Add(feedAuthorityFutureTolerance)) {
		return nil, errors.New("signed feed authority is issued in the future")
	}
	attestation, err := matchFeedAuthorityAttestation(document, source, indicators, now)
	if err != nil {
		return nil, err
	}
	if previous != nil && previous.Authority != nil {
		if previousAttestation, ok := authorityAttestationFor(previous.Authority, source.Key); ok {
			if attestation.Sequence < previousAttestation.Sequence {
				return nil, errors.New("signed feed authority attestation rollback rejected")
			}
		}
	}
	return document, nil
}

func loadFeedAuthorityDocument(root string) (*feedAuthorityDocument, error) {
	path := feedAuthorityDocPath(root)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("signed feed authority document is not provisioned")
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("signed feed authority document must be a regular non-reparse file")
	}
	if info.Size() <= 0 || info.Size() > maximumFeedAuthorityDocBytes {
		return nil, errors.New("signed feed authority document size rejected")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document feedAuthorityDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("signed feed authority document JSON rejected")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("signed feed authority document trailing data rejected")
	}
	seen := make(map[string]struct{}, len(document.Feeds))
	for _, attestation := range document.Feeds {
		if attestation.FeedKey == "" || len(attestation.FeedKey) > MaximumFeedIDBytes {
			return nil, errors.New("signed feed authority attestation feed rejected")
		}
		if _, duplicate := seen[attestation.FeedKey]; duplicate {
			return nil, errors.New("signed feed authority attestation duplicated")
		}
		seen[attestation.FeedKey] = struct{}{}
		if !validFeedAction(attestation.Action) || len(attestation.ContentSHA256) != 64 || attestation.ValidUntilUTC.IsZero() {
			return nil, errors.New("signed feed authority attestation metadata rejected")
		}
	}
	return &document, nil
}

func matchFeedAuthorityAttestation(document *feedAuthorityDocument, source Source, indicators []string, now time.Time) (FeedAuthorityAttestation, error) {
	attestation, ok := authorityAttestationFor(document, source.Key)
	if !ok {
		return FeedAuthorityAttestation{}, fmt.Errorf("signed feed authority has no attestation for %s", source.Key)
	}
	if attestation.Action != source.Action {
		return FeedAuthorityAttestation{}, errors.New("signed feed authority action does not match the catalog authority")
	}
	if attestation.Sequence == 0 {
		return FeedAuthorityAttestation{}, errors.New("signed feed authority attestation sequence rejected")
	}
	if attestation.ValidUntilUTC.Sub(document.GeneratedUTC) > maximumFeedAuthorityValidity {
		return FeedAuthorityAttestation{}, errors.New("signed feed authority validity window exceeds the maximum")
	}
	if document.GeneratedUTC.After(now.Add(feedAuthorityFutureTolerance)) {
		return FeedAuthorityAttestation{}, errors.New("signed feed authority generation is issued in the future")
	}
	if now.After(attestation.ValidUntilUTC) {
		return FeedAuthorityAttestation{}, errors.New("signed feed authority attestation has expired")
	}
	digest := digestIndicators(source.Key, source.Action, indicators)
	if !strings.EqualFold(digest, attestation.ContentSHA256) {
		return FeedAuthorityAttestation{}, errors.New("signed feed authority content digest mismatch")
	}
	return attestation, nil
}

func authorityAttestationFor(document *feedAuthorityDocument, feedKey string) (FeedAuthorityAttestation, bool) {
	if document == nil {
		return FeedAuthorityAttestation{}, false
	}
	for _, attestation := range document.Feeds {
		if attestation.FeedKey == feedKey {
			return attestation, true
		}
	}
	return FeedAuthorityAttestation{}, false
}

// verifyCachedAuthority re-verifies a cached generation against the pinned key
// ring, its embedded signed authority document and the hard validity window.
func (m *Manager) verifyCachedAuthority(snapshot *sourceSnapshot) error {
	m.authorityMu.RLock()
	configured := m.authorityConfigured
	authorityErr := m.authorityError
	state := m.authorityState
	keys := m.authorityKeys
	m.authorityMu.RUnlock()
	if !configured {
		return nil
	}
	if authorityErr != "" {
		return errors.New(authorityErr)
	}
	if snapshot.Authority == nil {
		return errors.New("cached feed generation has no signed authority attestation")
	}
	if snapshot.Authority.SchemaVersion != feedAuthoritySchemaVersion || snapshot.Authority.Sequence < state.LastSequence {
		return errors.New("cached feed authority sequence rejected")
	}
	if err := m.verifyFeedAuthorityDocument(snapshot.Authority, keys); err != nil {
		return err
	}
	attestation, err := matchFeedAuthorityAttestation(snapshot.Authority, Source{Key: snapshot.Key, Action: snapshot.Action}, snapshot.Indicators, m.effectiveNowUTC())
	if err != nil {
		return err
	}
	if attestation.Sequence == 0 {
		return errors.New("cached feed authority attestation sequence rejected")
	}
	return nil
}

// updateFeedAuthorityState records the accepted signed-document sequence so a
// replayed older document is rejected on the next synchronization.
func (m *Manager) updateFeedAuthorityState(document *feedAuthorityDocument) {
	if document == nil {
		return
	}
	m.authorityMu.Lock()
	defer m.authorityMu.Unlock()
	changed := false
	if document.Sequence > m.authorityState.LastSequence {
		m.authorityState.LastSequence = document.Sequence
		changed = true
	}
	if document.GeneratedUTC.After(m.authorityState.LastGeneratedUTC) {
		m.authorityState.LastGeneratedUTC = document.GeneratedUTC
		changed = true
	}
	if changed {
		_ = m.persistFeedAuthorityState(m.authorityState)
	}
}

// signatureHMACEqual is a small constant-time helper for the feed policy store.
func signatureHMACEqual(left, right string) bool {
	leftBytes, leftErr := hex.DecodeString(left)
	rightBytes, rightErr := hex.DecodeString(right)
	if leftErr != nil || rightErr != nil || len(leftBytes) != sha256.Size || len(rightBytes) != sha256.Size {
		return false
	}
	return hmac.Equal(leftBytes, rightBytes)
}

// feedPolicyMACKey is the derived key used by the feed override store.
func feedPolicyMACKey(rawKey []byte) []byte {
	derived := hmac.New(sha256.New, rawKey)
	_, _ = derived.Write([]byte("VGT-GEDEFENSE-FEED-POLICY-MAC-V1"))
	return derived.Sum(nil)
}
