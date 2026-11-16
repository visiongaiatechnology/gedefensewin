// STATUS: PLATIN VGT SUPREME

package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestReceiptRoundTrip(t *testing.T) {
	provider, privateKey := newTestKeyProvider(t)
	checkpoint := signedTestCheckpoint(t, provider)
	receipt := signedTestReceipt(t, privateKey, checkpoint, 42)
	if err := ValidateReceipt(receipt); err != nil {
		t.Fatalf("signed receipt is invalid: %v", err)
	}
	if err := VerifyReceipt(receipt, provider.Ed25519PublicKey()); err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	if err := BindReceipt(receipt, checkpoint); err != nil {
		t.Fatalf("bind receipt: %v", err)
	}
	encoded := encodeJSON(t, receipt)
	decoded, err := DecodeReceipt(encoded)
	if err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if !bytes.Equal(encodeJSON(t, decoded), encoded) {
		t.Fatal("receipt round trip is not byte-identical")
	}
}

func TestReceiptRejections(t *testing.T) {
	provider, privateKey := newTestKeyProvider(t)
	checkpoint := signedTestCheckpoint(t, provider)
	receipt := signedTestReceipt(t, privateKey, checkpoint, 7)
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate foreign key: %v", err)
	}
	_ = otherPublic

	t.Run("wrong verification key", func(t *testing.T) {
		if err := VerifyReceipt(receipt, otherPublic); !errors.Is(err, ErrReceiptInvalid) {
			t.Fatalf("error is %v", err)
		}
	})
	t.Run("forged signature", func(t *testing.T) {
		forged := receipt
		forged.Signature = ""
		forged, err = SignReceipt(forged, otherPrivate)
		if err != nil {
			t.Fatalf("sign forged receipt: %v", err)
		}
		if err := VerifyReceipt(forged, provider.Ed25519PublicKey()); !errors.Is(err, ErrReceiptInvalid) {
			t.Fatalf("error is %v", err)
		}
	})
	t.Run("binding mismatch", func(t *testing.T) {
		other := checkpoint
		other.CheckpointID = strings.Repeat("cd", 16)
		if err := BindReceipt(receipt, other); !errors.Is(err, ErrReceiptInvalid) {
			t.Fatalf("error is %v", err)
		}
	})
	t.Run("zero sequence", func(t *testing.T) {
		bad := receipt
		bad.WitnessSequence = 0
		if err := ValidateReceipt(bad); !errors.Is(err, ErrReceiptInvalid) {
			t.Fatalf("error is %v", err)
		}
	})
	t.Run("bad timestamp", func(t *testing.T) {
		bad := receipt
		bad.AcceptedAtUTC = "2026-01-01T00:00:00+01:00"
		if err := ValidateReceipt(bad); !errors.Is(err, ErrReceiptInvalid) {
			t.Fatalf("error is %v", err)
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		raw := append(bytes.TrimSuffix(encodeJSON(t, receipt), []byte("}")), []byte(`,"unknown":1}`)...)
		if _, err := DecodeReceipt(raw); !errors.Is(err, ErrReceiptInvalid) {
			t.Fatalf("error is %v", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		if _, err := DecodeReceipt(bytes.Repeat([]byte(" "), receiptMaxBytes+1)); !errors.Is(err, ErrDocumentTooLarge) {
			t.Fatalf("error is %v", err)
		}
	})
	t.Run("not an object", func(t *testing.T) {
		if _, err := DecodeReceipt([]byte(`"receipt"`)); !errors.Is(err, ErrReceiptInvalid) {
			t.Fatalf("error is %v", err)
		}
	})
}
