// STATUS: PLATIN VGT SUPREME

package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestNewStaticKeyProvider(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	outboxKey := bytes.Repeat([]byte{0x42}, outboxKeyBytes)
	provider, err := NewStaticKeyProvider(privateKey, outboxKey)
	if err != nil {
		t.Fatalf("NewStaticKeyProvider: %v", err)
	}
	if !bytes.Equal(provider.Ed25519PublicKey(), publicKey) {
		t.Fatal("provider returned a different public key")
	}
	if !bytes.Equal(provider.OutboxKey(), outboxKey) {
		t.Fatal("provider returned a different outbox key")
	}
	// The provider must copy its inputs.
	privateKey[0] ^= 0xff
	outboxKey[0] ^= 0xff
	if bytes.Equal(provider.OutboxKey(), outboxKey) {
		t.Fatal("provider aliased the caller's outbox key")
	}
	publicCopy := provider.Ed25519PublicKey()
	publicCopy[0] ^= 0xff
	if bytes.Equal(provider.Ed25519PublicKey(), publicCopy) {
		t.Fatal("provider aliased the returned public key")
	}
	if _, err := NewStaticKeyProvider(nil, outboxKey); !errors.Is(err, ErrKeyProvider) {
		t.Fatalf("nil private key error is %v", err)
	}
	if _, err := NewStaticKeyProvider(privateKey, []byte("short")); !errors.Is(err, ErrKeyProvider) {
		t.Fatalf("short outbox key error is %v", err)
	}
}

func TestStaticKeyProviderSignsAndFingerprint(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	publicKey := provider.Ed25519PublicKey()
	fingerprint := PublicKeyFingerprint(publicKey)
	if len(fingerprint) != 64 || !validLowerHex(fingerprint) {
		t.Fatalf("fingerprint %q is not a lowercase hex SHA-256 digest", fingerprint)
	}
	if PublicKeyFingerprint(nil) != "" {
		t.Fatal("invalid public key produced a fingerprint")
	}
	digest := []byte("a 32-byte digest used for signing!!")
	signature, err := provider.SignCheckpointDigest(digest)
	if err != nil {
		t.Fatalf("SignCheckpointDigest: %v", err)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, digest, signature) {
		t.Fatal("provider signature does not verify")
	}
}

func TestGenerateOutboxKey(t *testing.T) {
	first, err := GenerateOutboxKey()
	if err != nil {
		t.Fatalf("GenerateOutboxKey: %v", err)
	}
	second, err := GenerateOutboxKey()
	if err != nil {
		t.Fatalf("GenerateOutboxKey: %v", err)
	}
	if len(first) != outboxKeyBytes || len(second) != outboxKeyBytes {
		t.Fatalf("generated keys have lengths %d and %d", len(first), len(second))
	}
	if bytes.Equal(first, second) {
		t.Fatal("two generated outbox keys are identical")
	}
}
