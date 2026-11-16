// STATUS: PLATIN VGT SUPREME

package witness

// Signed witness checkpoint contract (schema vgt-gedefense-witness-checkpoint-v1).
//
// A checkpoint is the only document this package ever sends off the host: the
// authenticated ledger head, a segment window, a policy generation, the producing
// agent version and a signature. It carries no paths, no evidence content, no
// targets and no key material.
//
// Canonical form: the Go struct field order is the canonical field order, the
// encoded form is UTF-8 JSON with exactly one value and no map iteration. The
// signed digest is sha256(Domain || canonical body), where the body is every
// contract field except checkpoint_sha256 and signature; checkpoint_sha256 is that
// digest in lowercase hex and signature is the Ed25519 signature over the raw
// digest bytes. 18 contract fields plus the detached signature field form the wire
// object; checkpoint_sha256 is the integrity field of the 18.
//
// Decoding external checkpoints is untrusted-input handling: size bound, schema
// bound, no unknown/duplicate/missing/null fields, no trailing data, no repairs.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// CheckpointSchema is the only accepted checkpoint schema. Forward
	// compatibility is expressed by a new schema version, never by tolerating
	// additional fields in this one.
	CheckpointSchema = "vgt-gedefense-witness-checkpoint-v1"

	// checkpointDomain separates a checkpoint digest from every other digest.
	checkpointDomain = "VGT-GEDEFENSE-WITNESS-CHECKPOINT-V1\x00"

	checkpointHashAlg      = "sha256"
	checkpointSignatureAlg = "ed25519"

	// CheckpointMaxBytes bounds the document a decoder will even look at.
	CheckpointMaxBytes = 64 << 10

	checkpointIDBytes               = 16
	checkpointMaxHostIDBytes        = 128
	checkpointMaxAgentVersionBytes  = 64
	checkpointMinPlausibleYear      = 2000
	checkpointMaxPlausibleYear      = 2100
	checkpointTimestampLayout       = time.RFC3339
	checkpointSignatureEncodedBytes = 86 // 64 raw bytes in unpadded base64url
)

// maxCounter bounds every counter to the integer range a JSON consumer can hold
// exactly (2^53). A witness in another language must never see a rounded value.
const maxCounter = 1 << 53

var (
	// ErrCheckpointInvalid marks a structurally invalid or inconsistent checkpoint.
	ErrCheckpointInvalid = errors.New("witness checkpoint is invalid")
	// ErrCheckpointTooLarge marks a checkpoint document above its size bound.
	ErrCheckpointTooLarge = errors.New("witness checkpoint exceeds its size bound")
	// ErrCheckpointSignature marks a signature/fingerprint/digest mismatch.
	ErrCheckpointSignature = errors.New("witness checkpoint signature is invalid")
)

// checkpointFieldNames is the exact, required wire field set including the
// detached signature. Order is the canonical encoding order.
var checkpointFieldNames = []string{
	"schema", "checkpoint_id", "ledger_epoch", "sequence",
	"previous_checkpoint_sha256", "ledger_tip_sha256", "segment_first_sequence",
	"segment_last_sequence", "event_count", "window_start_utc", "window_end_utc",
	"host_id", "agent_version", "policy_generation", "hash_alg",
	"signature_alg", "public_key_fingerprint", "checkpoint_sha256", "signature",
}

var checkpointFieldSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(checkpointFieldNames))
	for _, name := range checkpointFieldNames {
		set[name] = struct{}{}
	}
	return set
}()

// Checkpoint is the exact wire object. Declaration order is the canonical order.
type Checkpoint struct {
	Schema                   string `json:"schema"`
	CheckpointID             string `json:"checkpoint_id"`
	LedgerEpoch              uint64 `json:"ledger_epoch"`
	Sequence                 uint64 `json:"sequence"`
	PreviousCheckpointSHA256 string `json:"previous_checkpoint_sha256"`
	LedgerTipSHA256          string `json:"ledger_tip_sha256"`
	SegmentFirstSequence     uint64 `json:"segment_first_sequence"`
	SegmentLastSequence      uint64 `json:"segment_last_sequence"`
	EventCount               uint64 `json:"event_count"`
	WindowStartUTC           string `json:"window_start_utc"`
	WindowEndUTC             string `json:"window_end_utc"`
	HostID                   string `json:"host_id"`
	AgentVersion             string `json:"agent_version"`
	PolicyGeneration         uint64 `json:"policy_generation"`
	HashAlg                  string `json:"hash_alg"`
	SignatureAlg             string `json:"signature_alg"`
	PublicKeyFingerprint     string `json:"public_key_fingerprint"`
	CheckpointSHA256         string `json:"checkpoint_sha256"`
	Signature                string `json:"signature"`
}

// checkpointBody is the signed subset of Checkpoint plus its integrity field is
// excluded: it is a distinct type so the encoder cannot accidentally include a
// signature that is being replaced or a digest that is being recomputed.
type checkpointBody struct {
	Schema                   string `json:"schema"`
	CheckpointID             string `json:"checkpoint_id"`
	LedgerEpoch              uint64 `json:"ledger_epoch"`
	Sequence                 uint64 `json:"sequence"`
	PreviousCheckpointSHA256 string `json:"previous_checkpoint_sha256"`
	LedgerTipSHA256          string `json:"ledger_tip_sha256"`
	SegmentFirstSequence     uint64 `json:"segment_first_sequence"`
	SegmentLastSequence      uint64 `json:"segment_last_sequence"`
	EventCount               uint64 `json:"event_count"`
	WindowStartUTC           string `json:"window_start_utc"`
	WindowEndUTC             string `json:"window_end_utc"`
	HostID                   string `json:"host_id"`
	AgentVersion             string `json:"agent_version"`
	PolicyGeneration         uint64 `json:"policy_generation"`
	HashAlg                  string `json:"hash_alg"`
	SignatureAlg             string `json:"signature_alg"`
	PublicKeyFingerprint     string `json:"public_key_fingerprint"`
}

func (c Checkpoint) body() checkpointBody {
	return checkpointBody{
		Schema: c.Schema, CheckpointID: c.CheckpointID, LedgerEpoch: c.LedgerEpoch,
		Sequence: c.Sequence, PreviousCheckpointSHA256: c.PreviousCheckpointSHA256,
		LedgerTipSHA256: c.LedgerTipSHA256, SegmentFirstSequence: c.SegmentFirstSequence,
		SegmentLastSequence: c.SegmentLastSequence, EventCount: c.EventCount,
		WindowStartUTC: c.WindowStartUTC, WindowEndUTC: c.WindowEndUTC, HostID: c.HostID,
		AgentVersion: c.AgentVersion, PolicyGeneration: c.PolicyGeneration,
		HashAlg: c.HashAlg, SignatureAlg: c.SignatureAlg,
		PublicKeyFingerprint: c.PublicKeyFingerprint,
	}
}

// NewCheckpointID returns a fresh 16-byte random checkpoint identifier as 32
// lowercase hex characters.
func NewCheckpointID() (string, error) {
	raw := make([]byte, checkpointIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("witness checkpoint id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// ComputeCheckpointDigest returns the domain-separated SHA-256 over the canonical
// checkpoint body (all contract fields except checkpoint_sha256 and signature).
func ComputeCheckpointDigest(checkpoint Checkpoint) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	payload, err := json.Marshal(checkpoint.body())
	if err != nil {
		return zero, fmt.Errorf("%w: canonical body cannot be encoded: %v", ErrCheckpointInvalid, err)
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(checkpointDomain))
	_, _ = hasher.Write(payload)
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

// SignCheckpoint signs the canonical digest with the key provider, sets the
// public-key fingerprint, checkpoint_sha256 and signature fields, and validates
// the result. Ed25519 is deterministic, so equal checkpoints sign identically.
func SignCheckpoint(checkpoint Checkpoint, signer KeyProvider) (Checkpoint, error) {
	if signer == nil {
		return Checkpoint{}, fmt.Errorf("%w: key provider is not configured", ErrKeyProvider)
	}
	publicKey := signer.Ed25519PublicKey()
	if len(publicKey) != ed25519.PublicKeySize {
		return Checkpoint{}, fmt.Errorf("%w: signing public key is invalid", ErrKeyProvider)
	}
	fingerprint := PublicKeyFingerprint(publicKey)
	if checkpoint.PublicKeyFingerprint != "" && subtle.ConstantTimeCompare([]byte(checkpoint.PublicKeyFingerprint), []byte(fingerprint)) != 1 {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint names a different signing key", ErrCheckpointInvalid)
	}
	checkpoint.PublicKeyFingerprint = fingerprint
	checkpoint.CheckpointSHA256 = ""
	checkpoint.Signature = ""
	digest, err := ComputeCheckpointDigest(checkpoint)
	if err != nil {
		return Checkpoint{}, err
	}
	signature, err := signer.SignCheckpointDigest(digest[:])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("witness checkpoint signing: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return Checkpoint{}, fmt.Errorf("%w: signer returned an invalid signature size", ErrCheckpointSignature)
	}
	checkpoint.CheckpointSHA256 = hex.EncodeToString(digest[:])
	checkpoint.Signature = base64.RawURLEncoding.EncodeToString(signature)
	if err := ValidateCheckpoint(checkpoint); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

// VerifyCheckpoint validates the checkpoint and verifies its Ed25519 signature
// against the public key. The digest and fingerprint comparisons are constant
// time; the signature is checked by ed25519.Verify.
func VerifyCheckpoint(checkpoint Checkpoint, publicKey ed25519.PublicKey) error {
	if err := ValidateCheckpoint(checkpoint); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verification key is invalid", ErrCheckpointSignature)
	}
	fingerprint := PublicKeyFingerprint(publicKey)
	if subtle.ConstantTimeCompare([]byte(checkpoint.PublicKeyFingerprint), []byte(fingerprint)) != 1 {
		return fmt.Errorf("%w: checkpoint fingerprint does not match the verification key", ErrCheckpointSignature)
	}
	digest, err := ComputeCheckpointDigest(checkpoint)
	if err != nil {
		return err
	}
	declared, err := hex.DecodeString(checkpoint.CheckpointSHA256)
	if err != nil || len(declared) != sha256.Size {
		return fmt.Errorf("%w: checkpoint digest is not canonical", ErrCheckpointSignature)
	}
	if subtle.ConstantTimeCompare(declared, digest[:]) != 1 {
		return fmt.Errorf("%w: checkpoint digest does not match its body", ErrCheckpointSignature)
	}
	signature, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: checkpoint signature is not canonical", ErrCheckpointSignature)
	}
	if !ed25519.Verify(publicKey, digest[:], signature) {
		return fmt.Errorf("%w: checkpoint signature does not verify", ErrCheckpointSignature)
	}
	return nil
}

// ValidateCheckpoint checks the full checkpoint contract, including that
// checkpoint_sha256 is the digest of the canonical body.
func ValidateCheckpoint(checkpoint Checkpoint) error {
	if checkpoint.Schema != CheckpointSchema {
		return fmt.Errorf("%w: schema %q is not %q", ErrCheckpointInvalid, checkpoint.Schema, CheckpointSchema)
	}
	if len(checkpoint.CheckpointID) != 2*checkpointIDBytes || !validLowerHex(checkpoint.CheckpointID) {
		return fmt.Errorf("%w: checkpoint_id is not 16 bytes of lowercase hex", ErrCheckpointInvalid)
	}
	if checkpoint.LedgerEpoch > maxCounter || checkpoint.Sequence > maxCounter ||
		checkpoint.SegmentFirstSequence > maxCounter || checkpoint.SegmentLastSequence > maxCounter ||
		checkpoint.EventCount > maxCounter || checkpoint.PolicyGeneration > maxCounter {
		return fmt.Errorf("%w: a counter exceeds the JSON-safe bound", ErrCheckpointInvalid)
	}
	if checkpoint.Sequence == 0 {
		return fmt.Errorf("%w: sequence must be greater than zero", ErrCheckpointInvalid)
	}
	if checkpoint.PreviousCheckpointSHA256 != "" && !validDigestHex(checkpoint.PreviousCheckpointSHA256) {
		return fmt.Errorf("%w: previous_checkpoint_sha256 is not a SHA-256 digest", ErrCheckpointInvalid)
	}
	if !validDigestHex(checkpoint.LedgerTipSHA256) {
		return fmt.Errorf("%w: ledger_tip_sha256 is not a SHA-256 digest", ErrCheckpointInvalid)
	}
	if checkpoint.SegmentFirstSequence == 0 || checkpoint.SegmentFirstSequence > checkpoint.SegmentLastSequence {
		return fmt.Errorf("%w: segment window is not ordered", ErrCheckpointInvalid)
	}
	if checkpoint.SegmentLastSequence != checkpoint.Sequence {
		return fmt.Errorf("%w: segment_last_sequence must equal sequence", ErrCheckpointInvalid)
	}
	if checkpoint.EventCount != checkpoint.SegmentLastSequence-checkpoint.SegmentFirstSequence+1 {
		return fmt.Errorf("%w: event_count does not match the segment window", ErrCheckpointInvalid)
	}
	windowStart, ok := parseCanonicalUTC(checkpoint.WindowStartUTC)
	if !ok {
		return fmt.Errorf("%w: window_start_utc is not a canonical plausible UTC timestamp", ErrCheckpointInvalid)
	}
	windowEnd, ok := parseCanonicalUTC(checkpoint.WindowEndUTC)
	if !ok {
		return fmt.Errorf("%w: window_end_utc is not a canonical plausible UTC timestamp", ErrCheckpointInvalid)
	}
	if windowEnd.Before(windowStart) {
		return fmt.Errorf("%w: window_end_utc precedes window_start_utc", ErrCheckpointInvalid)
	}
	if err := validateHostID(checkpoint.HostID); err != nil {
		return fmt.Errorf("%w: %v", ErrCheckpointInvalid, err)
	}
	if err := validateAgentVersion(checkpoint.AgentVersion); err != nil {
		return fmt.Errorf("%w: %v", ErrCheckpointInvalid, err)
	}
	if checkpoint.HashAlg != checkpointHashAlg {
		return fmt.Errorf("%w: hash_alg must be %q", ErrCheckpointInvalid, checkpointHashAlg)
	}
	if checkpoint.SignatureAlg != checkpointSignatureAlg {
		return fmt.Errorf("%w: signature_alg must be %q", ErrCheckpointInvalid, checkpointSignatureAlg)
	}
	if !validDigestHex(checkpoint.PublicKeyFingerprint) {
		return fmt.Errorf("%w: public_key_fingerprint is not a SHA-256 digest", ErrCheckpointInvalid)
	}
	if !validDigestHex(checkpoint.CheckpointSHA256) {
		return fmt.Errorf("%w: checkpoint_sha256 is not a SHA-256 digest", ErrCheckpointInvalid)
	}
	if len(checkpoint.Signature) != checkpointSignatureEncodedBytes {
		return fmt.Errorf("%w: signature is not a canonical base64url Ed25519 signature", ErrCheckpointInvalid)
	}
	digest, err := ComputeCheckpointDigest(checkpoint)
	if err != nil {
		return err
	}
	declared, err := hex.DecodeString(checkpoint.CheckpointSHA256)
	if err != nil || subtle.ConstantTimeCompare(declared, digest[:]) != 1 {
		return fmt.Errorf("%w: checkpoint_sha256 does not match the canonical body", ErrCheckpointInvalid)
	}
	signature, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != checkpoint.Signature {
		return fmt.Errorf("%w: signature is not a canonical base64url Ed25519 signature", ErrCheckpointInvalid)
	}
	return nil
}

// EncodeCheckpoint returns the canonical JSON form of a signed checkpoint.
func EncodeCheckpoint(checkpoint Checkpoint) ([]byte, error) {
	if err := ValidateCheckpoint(checkpoint); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(checkpoint)
	if err != nil {
		return nil, fmt.Errorf("witness checkpoint encoding: %w", err)
	}
	return encoded, nil
}

// DecodeCheckpoint parses one external checkpoint document strictly. Unknown,
// duplicate, missing and null fields, trailing data and oversized documents are
// rejected; the decoded value is validated before it is returned.
func DecodeCheckpoint(data []byte) (Checkpoint, error) {
	if len(data) == 0 {
		return Checkpoint{}, fmt.Errorf("%w: document is empty", ErrCheckpointInvalid)
	}
	if len(data) > CheckpointMaxBytes {
		return Checkpoint{}, fmt.Errorf("%w: %d > %d bytes", ErrCheckpointTooLarge, len(data), CheckpointMaxBytes)
	}
	trimmed := bytes.TrimSpace(data)
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	token, err := decoder.Token()
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: not valid JSON: %v", ErrCheckpointInvalid, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return Checkpoint{}, fmt.Errorf("%w: must be a JSON object", ErrCheckpointInvalid)
	}
	seen := make(map[string]struct{}, len(checkpointFieldNames))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return Checkpoint{}, fmt.Errorf("%w: malformed object: %v", ErrCheckpointInvalid, err)
		}
		name, ok := token.(string)
		if !ok {
			return Checkpoint{}, fmt.Errorf("%w: non-string field name", ErrCheckpointInvalid)
		}
		if _, allowed := checkpointFieldSet[name]; !allowed {
			return Checkpoint{}, fmt.Errorf("%w: unknown field %q", ErrCheckpointInvalid, name)
		}
		if _, duplicate := seen[name]; duplicate {
			return Checkpoint{}, fmt.Errorf("%w: duplicate field %q", ErrCheckpointInvalid, name)
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return Checkpoint{}, fmt.Errorf("%w: field %q is not valid JSON: %v", ErrCheckpointInvalid, name, err)
		}
		if jsonLiteralMessage(value) {
			return Checkpoint{}, fmt.Errorf("%w: field %q is null", ErrCheckpointInvalid, name)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: malformed object: %v", ErrCheckpointInvalid, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Checkpoint{}, fmt.Errorf("%w: trailing data", ErrCheckpointInvalid)
	}
	for _, name := range checkpointFieldNames {
		if _, present := seen[name]; !present {
			return Checkpoint{}, fmt.Errorf("%w: missing field %q", ErrCheckpointInvalid, name)
		}
	}
	strict := json.NewDecoder(bytes.NewReader(trimmed))
	strict.DisallowUnknownFields()
	var checkpoint Checkpoint
	if err := strict.Decode(&checkpoint); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: %v", ErrCheckpointInvalid, err)
	}
	if err := ValidateCheckpoint(checkpoint); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

// parseCanonicalUTC accepts exactly the canonical UTC RFC3339 spelling within a
// plausible year range. A fractional second or an offset form would allow several
// encodings of one instant, and the signature covers the spelling.
func parseCanonicalUTC(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(checkpointTimestampLayout, value)
	if err != nil || parsed.UTC().Format(checkpointTimestampLayout) != value {
		return time.Time{}, false
	}
	year := parsed.UTC().Year()
	if year < checkpointMinPlausibleYear || year >= checkpointMaxPlausibleYear {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func validDigestHex(value string) bool {
	return len(value) == 2*sha256.Size && validLowerHex(value)
}

func validLowerHex(value string) bool {
	for index := 0; index < len(value); index++ {
		char := value[index]
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
