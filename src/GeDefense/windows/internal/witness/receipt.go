// STATUS: PLATIN VGT SUPREME

package witness

// Signed witness receipts. A receipt is the only acknowledgement the package
// accepts from a witness: it binds the exact checkpoint id and checkpoint digest,
// carries a strictly increasing witness sequence and is signed by the pinned
// Ed25519 receipt key. Decoding is strict; a receipt that does not verify never
// removes anything from the outbox.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	// ReceiptSchema is the only accepted receipt schema.
	ReceiptSchema = "vgt-gedefense-witness-receipt-v1"
	// receiptDomain separates a receipt signature from every other signature.
	receiptDomain = "VGT-GEDEFENSE-WITNESS-RECEIPT-V1\x00"
	// receiptMaxBytes bounds the receipt document a decoder will look at.
	receiptMaxBytes = 8 << 10
	// receiptMaxIDBytes bounds a witness receipt identifier.
	receiptMaxIDBytes = 128
	// receiptFutureSkew bounds how far a receipt timestamp may be in the future.
	receiptFutureSkew = 5 * time.Minute
)

var (
	// ErrReceiptInvalid marks a malformed or unverifiable witness receipt.
	ErrReceiptInvalid = errors.New("witness receipt is invalid")
)

// Receipt is the signed acknowledgement of one checkpoint.
type Receipt struct {
	Schema           string `json:"schema"`
	ReceiptID        string `json:"receipt_id"`
	CheckpointID     string `json:"checkpoint_id"`
	CheckpointSHA256 string `json:"checkpoint_sha256"`
	WitnessSequence  uint64 `json:"witness_sequence"`
	AcceptedAtUTC    string `json:"accepted_at_utc"`
	Signature        string `json:"signature"`
}

// receiptBody is the signed subset of Receipt.
type receiptBody struct {
	Schema           string `json:"schema"`
	ReceiptID        string `json:"receipt_id"`
	CheckpointID     string `json:"checkpoint_id"`
	CheckpointSHA256 string `json:"checkpoint_sha256"`
	WitnessSequence  uint64 `json:"witness_sequence"`
	AcceptedAtUTC    string `json:"accepted_at_utc"`
}

func (r Receipt) body() receiptBody {
	return receiptBody{
		Schema: r.Schema, ReceiptID: r.ReceiptID, CheckpointID: r.CheckpointID,
		CheckpointSHA256: r.CheckpointSHA256, WitnessSequence: r.WitnessSequence,
		AcceptedAtUTC: r.AcceptedAtUTC,
	}
}

// receiptDigest returns the domain-separated SHA-256 over the canonical body.
func receiptDigest(receipt Receipt) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	payload, err := json.Marshal(receipt.body())
	if err != nil {
		return zero, fmt.Errorf("%w: canonical body cannot be encoded: %v", ErrReceiptInvalid, err)
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(receiptDomain))
	_, _ = hasher.Write(payload)
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

// SignReceipt signs a receipt body with the witness receipt key. It exists so the
// test witness server and offline import tools can produce exactly the documents
// VerifyReceipt accepts; production witnesses sign on their own side.
func SignReceipt(receipt Receipt, privateKey ed25519.PrivateKey) (Receipt, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Receipt{}, fmt.Errorf("%w: receipt signing key is invalid", ErrReceiptInvalid)
	}
	receipt.Signature = ""
	digest, err := receiptDigest(receipt)
	if err != nil {
		return Receipt{}, err
	}
	receipt.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, digest[:]))
	if err := ValidateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// ValidateReceipt checks the unsigned shape of a receipt. It rejects instead of
// repairing: foreign ids, non-canonical timestamps and malformed signatures never
// reach an outbox acknowledgement.
func ValidateReceipt(receipt Receipt) error {
	if receipt.Schema != ReceiptSchema {
		return fmt.Errorf("%w: schema %q is not %q", ErrReceiptInvalid, receipt.Schema, ReceiptSchema)
	}
	if err := validateReceiptID(receipt.ReceiptID); err != nil {
		return err
	}
	if len(receipt.CheckpointID) != 2*checkpointIDBytes || !validLowerHex(receipt.CheckpointID) {
		return fmt.Errorf("%w: checkpoint_id is not 16 bytes of lowercase hex", ErrReceiptInvalid)
	}
	if !validDigestHex(receipt.CheckpointSHA256) {
		return fmt.Errorf("%w: checkpoint_sha256 is not a SHA-256 digest", ErrReceiptInvalid)
	}
	if receipt.WitnessSequence == 0 || receipt.WitnessSequence > maxCounter {
		return fmt.Errorf("%w: witness_sequence is zero or exceeds the JSON-safe bound", ErrReceiptInvalid)
	}
	if _, ok := parseCanonicalUTC(receipt.AcceptedAtUTC); !ok {
		return fmt.Errorf("%w: accepted_at_utc is not a canonical plausible UTC timestamp", ErrReceiptInvalid)
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != receipt.Signature {
		return fmt.Errorf("%w: signature is not a canonical base64url Ed25519 signature", ErrReceiptInvalid)
	}
	return nil
}

// VerifyReceipt validates the receipt and verifies its Ed25519 signature against
// the pinned witness receipt key. The declared checkpoint digest is included in
// the signed body; the comparison with the sent checkpoint happens in the client.
func VerifyReceipt(receipt Receipt, publicKey ed25519.PublicKey) error {
	if err := ValidateReceipt(receipt); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: receipt verification key is invalid", ErrReceiptInvalid)
	}
	digest, err := receiptDigest(receipt)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil {
		return fmt.Errorf("%w: receipt signature is not canonical", ErrReceiptInvalid)
	}
	if !ed25519.Verify(publicKey, digest[:], signature) {
		return fmt.Errorf("%w: receipt signature does not verify", ErrReceiptInvalid)
	}
	return nil
}

// DecodeReceipt parses one external receipt document strictly.
func DecodeReceipt(data []byte) (Receipt, error) {
	var receipt Receipt
	if err := decodeStrictJSON(data, receiptMaxBytes, &receipt); err != nil {
		return Receipt{}, fmt.Errorf("%w: %w", ErrReceiptInvalid, err)
	}
	if err := ValidateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// BindReceipt reports whether an otherwise valid receipt acknowledges exactly the
// supplied checkpoint.
func BindReceipt(receipt Receipt, checkpoint Checkpoint) error {
	if receipt.CheckpointID != checkpoint.CheckpointID {
		return fmt.Errorf("%w: receipt names a different checkpoint id", ErrReceiptInvalid)
	}
	declared, err := hexDecodeDigest(receipt.CheckpointSHA256)
	if err != nil {
		return fmt.Errorf("%w: receipt checkpoint_sha256 is not canonical", ErrReceiptInvalid)
	}
	expected, err := hexDecodeDigest(checkpoint.CheckpointSHA256)
	if err != nil {
		return fmt.Errorf("%w: checkpoint digest is not canonical", ErrCheckpointInvalid)
	}
	if subtle.ConstantTimeCompare(declared, expected) != 1 {
		return fmt.Errorf("%w: receipt names a different checkpoint digest", ErrReceiptInvalid)
	}
	return nil
}

// validateReceiptID bounds the witness-chosen receipt identifier charset.
func validateReceiptID(value string) error {
	if value == "" || len(value) > receiptMaxIDBytes {
		return fmt.Errorf("%w: receipt_id is empty or oversized", ErrReceiptInvalid)
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		alnum := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if !alnum && char != '.' && char != '-' && char != '_' && char != ':' {
			return fmt.Errorf("%w: receipt_id contains an unsupported character", ErrReceiptInvalid)
		}
	}
	return nil
}

// hexDecodeDigest decodes a canonical 64-character lowercase hex digest.
func hexDecodeDigest(value string) ([]byte, error) {
	if !validDigestHex(value) {
		return nil, errors.New("not a lowercase hex SHA-256 digest")
	}
	return hex.DecodeString(value)
}
