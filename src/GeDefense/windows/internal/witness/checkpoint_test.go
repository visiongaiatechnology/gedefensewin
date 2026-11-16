// STATUS: PLATIN VGT SUPREME

package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestCheckpointRoundTripAndVerify(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	checkpoint := signedTestCheckpoint(t, provider)
	if err := ValidateCheckpoint(checkpoint); err != nil {
		t.Fatalf("signed checkpoint is invalid: %v", err)
	}
	if err := VerifyCheckpoint(checkpoint, provider.Ed25519PublicKey()); err != nil {
		t.Fatalf("verify signed checkpoint: %v", err)
	}
	encoded, err := EncodeCheckpoint(checkpoint)
	if err != nil {
		t.Fatalf("encode checkpoint: %v", err)
	}
	decoded, err := DecodeCheckpoint(encoded)
	if err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	reencoded, err := EncodeCheckpoint(decoded)
	if err != nil {
		t.Fatalf("re-encode decoded checkpoint: %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("checkpoint round trip is not byte-identical")
	}
	ids := map[string]struct{}{}
	for index := 0; index < 4; index++ {
		id, err := NewCheckpointID()
		if err != nil {
			t.Fatalf("new checkpoint id: %v", err)
		}
		if len(id) != 32 || !validLowerHex(id) {
			t.Fatalf("checkpoint id %q is not 16 bytes of lowercase hex", id)
		}
		if _, duplicate := ids[id]; duplicate {
			t.Fatal("checkpoint id generator repeated a value")
		}
		ids[id] = struct{}{}
	}
}

func TestCheckpointDigestIsDeterministicAndDomainSeparated(t *testing.T) {
	body := testCheckpointBody()
	first, err := ComputeCheckpointDigest(body)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	second, err := ComputeCheckpointDigest(body)
	if err != nil {
		t.Fatalf("compute digest again: %v", err)
	}
	if first != second {
		t.Fatal("checkpoint digest is not deterministic")
	}
	plain := sha256.Sum256(encodeJSON(t, body.body()))
	if first == plain {
		t.Fatal("checkpoint digest is missing the domain separation prefix")
	}
	mutated := body
	mutated.LedgerTipSHA256 = testDigest("another-tip")
	other, err := ComputeCheckpointDigest(mutated)
	if err != nil {
		t.Fatalf("compute mutated digest: %v", err)
	}
	if first == other {
		t.Fatal("checkpoint digest ignored a body change")
	}
}

func TestDecodeCheckpointStrictness(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	checkpoint := signedTestCheckpoint(t, provider)
	encoded, err := EncodeCheckpoint(checkpoint)
	if err != nil {
		t.Fatalf("encode checkpoint: %v", err)
	}
	hostField := []byte(`"host_id":"` + testHostID + `",`)
	schemaField := []byte(`{"schema":"` + CheckpointSchema + `",`)
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrCheckpointInvalid},
		{"not an object", []byte(`[]`), ErrCheckpointInvalid},
		{"oversized", bytes.Repeat([]byte(" "), CheckpointMaxBytes+1), ErrCheckpointTooLarge},
		{"unknown field", append(bytes.TrimSuffix(encoded, []byte("}")), []byte(`,"unknown_field":1}`)...), ErrCheckpointInvalid},
		{"duplicate field", bytes.Replace(encoded, schemaField, append(append([]byte{}, schemaField...), schemaField[1:]...), 1), ErrCheckpointInvalid},
		{"missing field", bytes.Replace(encoded, hostField, nil, 1), ErrCheckpointInvalid},
		{"null field", bytes.Replace(encoded, hostField, []byte(`"host_id":null,`), 1), ErrCheckpointInvalid},
		{"trailing data", append(append([]byte{}, encoded...), []byte(` {}`)...), ErrCheckpointInvalid},
		{"truncated", encoded[:len(encoded)/2], ErrCheckpointInvalid},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := DecodeCheckpoint(testCase.data)
			if err == nil {
				t.Fatal("strict decoder accepted a malformed document")
			}
			if !errors.Is(err, testCase.want) {
				t.Fatalf("error %v does not wrap %v", err, testCase.want)
			}
		})
	}
}

func TestCheckpointTamperRejected(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	checkpoint := signedTestCheckpoint(t, provider)
	tampered := checkpoint
	tampered.LedgerTipSHA256 = testDigest("tampered-tip")
	if err := VerifyCheckpoint(tampered, provider.Ed25519PublicKey()); err == nil {
		t.Fatal("tampered checkpoint body verified")
	}
	tampered = checkpoint
	tampered.Sequence = checkpoint.Sequence + 1
	if err := VerifyCheckpoint(tampered, provider.Ed25519PublicKey()); err == nil {
		t.Fatal("tampered sequence verified")
	}
	digest, err := ComputeCheckpointDigest(checkpoint)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate foreign key: %v", err)
	}
	forged := checkpoint
	forged.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(otherPrivate, digest[:]))
	if err := VerifyCheckpoint(forged, provider.Ed25519PublicKey()); !errors.Is(err, ErrCheckpointSignature) {
		t.Fatalf("forged signature error is %v, want ErrCheckpointSignature", err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate foreign public key: %v", err)
	}
	if err := VerifyCheckpoint(checkpoint, otherPublic); !errors.Is(err, ErrCheckpointSignature) {
		t.Fatalf("wrong verification key error is %v, want ErrCheckpointSignature", err)
	}
}

func TestValidateCheckpointRanges(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	base := signedTestCheckpoint(t, provider)
	cases := []struct {
		name string
		edit func(*Checkpoint)
	}{
		{"zero sequence", func(checkpoint *Checkpoint) { checkpoint.Sequence = 0; checkpoint.SegmentLastSequence = 0 }},
		{"bad checkpoint id", func(checkpoint *Checkpoint) { checkpoint.CheckpointID = "not-hex" }},
		{"bad previous digest", func(checkpoint *Checkpoint) { checkpoint.PreviousCheckpointSHA256 = strings.Repeat("zz", 32) }},
		{"bad tip digest", func(checkpoint *Checkpoint) { checkpoint.LedgerTipSHA256 = "short" }},
		{"unordered segment", func(checkpoint *Checkpoint) { checkpoint.SegmentFirstSequence = 6 }},
		{"segment end mismatch", func(checkpoint *Checkpoint) { checkpoint.SegmentLastSequence = 4 }},
		{"event count mismatch", func(checkpoint *Checkpoint) { checkpoint.EventCount = 2 }},
		{"window offset form", func(checkpoint *Checkpoint) { checkpoint.WindowStartUTC = "2026-01-01T00:00:00+00:00" }},
		{"window reversed", func(checkpoint *Checkpoint) { checkpoint.WindowEndUTC = "2025-12-31T00:00:00Z" }},
		{"window implausible", func(checkpoint *Checkpoint) { checkpoint.WindowStartUTC = "1970-01-01T00:00:00Z" }},
		{"bad host id", func(checkpoint *Checkpoint) { checkpoint.HostID = "bad host" }},
		{"empty agent version", func(checkpoint *Checkpoint) { checkpoint.AgentVersion = "" }},
		{"bad hash alg", func(checkpoint *Checkpoint) { checkpoint.HashAlg = "sha1" }},
		{"bad signature alg", func(checkpoint *Checkpoint) { checkpoint.SignatureAlg = "rsa" }},
		{"counter overflow", func(checkpoint *Checkpoint) { checkpoint.PolicyGeneration = maxCounter + 1 }},
		{"bad signature encoding", func(checkpoint *Checkpoint) { checkpoint.Signature = "***" }},
		{"short signature", func(checkpoint *Checkpoint) {
			checkpoint.Signature = base64.RawURLEncoding.EncodeToString([]byte("short"))
		}},
		{"bad checkpoint digest", func(checkpoint *Checkpoint) { checkpoint.CheckpointSHA256 = testDigest("other") }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			checkpoint := base
			testCase.edit(&checkpoint)
			if err := ValidateCheckpoint(checkpoint); !errors.Is(err, ErrCheckpointInvalid) {
				t.Fatalf("ValidateCheckpoint error is %v, want ErrCheckpointInvalid", err)
			}
		})
	}
	// The untouched value must remain valid.
	if err := ValidateCheckpoint(base); err != nil {
		t.Fatalf("base checkpoint is invalid: %v", err)
	}
	// A checkpoint with a canonical digest but a non-hex signature must also fail.
	body := testCheckpointBody()
	digest, err := ComputeCheckpointDigest(body)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	body.CheckpointSHA256 = hex.EncodeToString(digest[:])
	if err := ValidateCheckpoint(body); err == nil {
		t.Fatal("checkpoint without a signature validated")
	}
}
