// STATUS: PLATIN VGT SUPREME

package witness

// Air-gap export/import token (Mode B).
//
// A token is vgtw1:<base64url> with RawURLEncoding (no padding) and a total
// length of at most 2 KiB, small enough for a QR symbol. Its payload is one
// strict JSON object containing the schema, the producing host id, the export
// time, a domain-separated batch digest and 1..4 signed checkpoints. The
// checkpoints carry their Ed25519 signature and public key fingerprint; no
// private key, outbox key or endpoint ever enters a token.
//
// Import is untrusted input: bounded size, exact prefix, canonical base64url,
// one strict JSON object, validated metadata, recomputed batch digest, and every
// checkpoint signature verified against the expected public key before anything
// is returned. Error classes are explicit so the caller can map rejection reasons.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// ExportSchema is the only accepted air-gap export schema.
	ExportSchema = "vgt-gedefense-witness-export-v1"
	// ExportTokenPrefix identifies the compact offline form.
	ExportTokenPrefix = "vgtw1:"
	// ExportMaxTokenBytes is the hard total length of one compact token.
	ExportMaxTokenBytes = 2048
	// ExportMaxCheckpoints bounds the batch a token may carry.
	ExportMaxCheckpoints = 4

	exportDomain       = "VGT-GEDEFENSE-WITNESS-EXPORT-V1\x00"
	exportMaxBytes     = 5120
	exportMaxHostBytes = checkpointMaxHostIDBytes
)

var (
	// ErrExportInvalid marks a malformed or unverifiable export document.
	ErrExportInvalid = errors.New("witness export is invalid")
	// ErrExportTooLarge marks a token above the 2 KiB bound.
	ErrExportTooLarge = errors.New("witness export exceeds the 2 KiB token bound")
)

// ExportPayload is the JSON payload inside a vgtw1 token.
type ExportPayload struct {
	Schema        string       `json:"schema"`
	HostID        string       `json:"host_id"`
	ExportedAtUTC string       `json:"exported_at_utc"`
	BatchSHA256   string       `json:"batch_sha256"`
	Checkpoints   []Checkpoint `json:"checkpoints"`
}

// batchDigest is the domain-separated SHA-256 over the canonical checkpoint list.
func batchDigest(checkpoints []Checkpoint) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	encoded, err := json.Marshal(checkpoints)
	if err != nil {
		return zero, fmt.Errorf("%w: checkpoint batch cannot be encoded: %v", ErrExportInvalid, err)
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(exportDomain))
	_, _ = hasher.Write(encoded)
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

// ExportToken builds the deterministic, bounded vgtw1 token for a signed
// checkpoint batch. exportedAt must be a non-zero, canonical second-precision UTC
// instant; equal inputs produce byte-identical tokens.
func ExportToken(checkpoints []Checkpoint, hostID string, exportedAt time.Time) (string, error) {
	if len(checkpoints) == 0 || len(checkpoints) > ExportMaxCheckpoints {
		return "", fmt.Errorf("%w: a token carries 1..%d checkpoints", ErrExportInvalid, ExportMaxCheckpoints)
	}
	if err := validateHostID(hostID); err != nil {
		return "", fmt.Errorf("%w: %v", ErrExportInvalid, err)
	}
	if exportedAt.IsZero() {
		return "", fmt.Errorf("%w: export time is required", ErrExportInvalid)
	}
	for index, checkpoint := range checkpoints {
		if err := ValidateCheckpoint(checkpoint); err != nil {
			return "", fmt.Errorf("%w: checkpoint %d: %v", ErrExportInvalid, index, err)
		}
	}
	digest, err := batchDigest(checkpoints)
	if err != nil {
		return "", err
	}
	payload := ExportPayload{
		Schema:        ExportSchema,
		HostID:        hostID,
		ExportedAtUTC: exportedAt.UTC().Format(checkpointTimestampLayout),
		BatchSHA256:   hex.EncodeToString(digest[:]),
		Checkpoints:   append([]Checkpoint(nil), checkpoints...),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("witness export encoding: %w", err)
	}
	token := ExportTokenPrefix + base64.RawURLEncoding.EncodeToString(encoded)
	if len(token) > ExportMaxTokenBytes {
		return "", fmt.Errorf("%w: %d > %d characters", ErrExportTooLarge, len(token), ExportMaxTokenBytes)
	}
	return token, nil
}

// ImportToken validates a vgtw1 token and verifies every checkpoint signature
// against publicKey. The returned payload has been fully authenticated.
func ImportToken(token string, publicKey ed25519.PublicKey) (ExportPayload, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return ExportPayload{}, fmt.Errorf("%w: verification key is invalid", ErrExportInvalid)
	}
	if token == "" {
		return ExportPayload{}, fmt.Errorf("%w: token is empty", ErrExportInvalid)
	}
	if len(token) > ExportMaxTokenBytes {
		return ExportPayload{}, fmt.Errorf("%w: %d > %d characters", ErrExportTooLarge, len(token), ExportMaxTokenBytes)
	}
	if !strings.HasPrefix(token, ExportTokenPrefix) {
		return ExportPayload{}, fmt.Errorf("%w: token prefix is not %q", ErrExportInvalid, ExportTokenPrefix)
	}
	encoded := token[len(ExportTokenPrefix):]
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ExportPayload{}, fmt.Errorf("%w: token body is not canonical base64url", ErrExportInvalid)
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return ExportPayload{}, fmt.Errorf("%w: token body is not canonical base64url", ErrExportInvalid)
	}
	if len(decoded) > exportMaxBytes {
		return ExportPayload{}, fmt.Errorf("%w: payload exceeds %d bytes", ErrExportInvalid, exportMaxBytes)
	}
	var payload ExportPayload
	if err := decodeStrictJSON(decoded, exportMaxBytes, &payload); err != nil {
		return ExportPayload{}, fmt.Errorf("%w: %v", ErrExportInvalid, err)
	}
	if payload.Schema != ExportSchema {
		return ExportPayload{}, fmt.Errorf("%w: schema %q is not %q", ErrExportInvalid, payload.Schema, ExportSchema)
	}
	if len(payload.HostID) > exportMaxHostBytes {
		return ExportPayload{}, fmt.Errorf("%w: host id is oversized", ErrExportInvalid)
	}
	if err := validateHostID(payload.HostID); err != nil {
		return ExportPayload{}, fmt.Errorf("%w: %v", ErrExportInvalid, err)
	}
	if _, ok := parseCanonicalUTC(payload.ExportedAtUTC); !ok {
		return ExportPayload{}, fmt.Errorf("%w: exported_at_utc is not canonical UTC", ErrExportInvalid)
	}
	if len(payload.Checkpoints) == 0 || len(payload.Checkpoints) > ExportMaxCheckpoints {
		return ExportPayload{}, fmt.Errorf("%w: a token carries 1..%d checkpoints", ErrExportInvalid, ExportMaxCheckpoints)
	}
	if !validDigestHex(payload.BatchSHA256) {
		return ExportPayload{}, fmt.Errorf("%w: batch_sha256 is not a SHA-256 digest", ErrExportInvalid)
	}
	for index, checkpoint := range payload.Checkpoints {
		if err := VerifyCheckpoint(checkpoint, publicKey); err != nil {
			return ExportPayload{}, fmt.Errorf("%w: checkpoint %d: %v", ErrExportInvalid, index, err)
		}
	}
	digest, err := batchDigest(payload.Checkpoints)
	if err != nil {
		return ExportPayload{}, err
	}
	declared, err := hex.DecodeString(payload.BatchSHA256)
	if err != nil || subtle.ConstantTimeCompare(declared, digest[:]) != 1 {
		return ExportPayload{}, fmt.Errorf("%w: batch_sha256 does not match the checkpoint batch", ErrExportInvalid)
	}
	return payload, nil
}
