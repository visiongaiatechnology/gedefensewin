// STATUS: PLATIN VGT SUPREME

package witness

// Key material boundaries. The witness package never generates, persists or
// exports an Ed25519 private key; it asks a KeyProvider to sign one digest and it
// asks for the public halves only for fingerprints. The AES-256 key of the outbox
// is supplied the same way. This file also contains the one production
// implementation, which the application may use when the evidence ledger already
// owns an Ed25519 key and an outbox key.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrKeyProvider marks a missing, malformed or unusable key provider.
var ErrKeyProvider = errors.New("witness key provider is invalid")

// KeyProvider supplies the two secrets the witness needs, without exposing them
// beyond the exact operations that require them.
type KeyProvider interface {
	// Ed25519PublicKey returns the checkpoint signing public key.
	Ed25519PublicKey() ed25519.PublicKey
	// SignCheckpointDigest signs the 32-byte domain-separated checkpoint digest
	// with the Ed25519 private key and returns a 64-byte signature.
	SignCheckpointDigest(digest []byte) ([]byte, error)
	// OutboxKey returns the 32-byte AES-256-GCM key of the encrypted outbox.
	OutboxKey() []byte
}

// staticKeyProvider is the in-process KeyProvider implementation.
type staticKeyProvider struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	outboxKey  []byte
}

// NewStaticKeyProvider returns a KeyProvider over a caller-owned Ed25519 private
// key and a 32-byte AES key. Both inputs are copied; later caller mutations do
// not affect the provider.
func NewStaticKeyProvider(privateKey ed25519.PrivateKey, outboxKey []byte) (KeyProvider, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key must be %d bytes", ErrKeyProvider, ed25519.PrivateKeySize)
	}
	if len(outboxKey) != outboxKeyBytes {
		return nil, fmt.Errorf("%w: outbox key must be %d bytes", ErrKeyProvider, outboxKeyBytes)
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key has no usable public key", ErrKeyProvider)
	}
	return &staticKeyProvider{
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
		outboxKey:  append([]byte(nil), outboxKey...),
	}, nil
}

// Ed25519PublicKey returns a copy of the checkpoint signing public key.
func (p *staticKeyProvider) Ed25519PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), p.publicKey...)
}

// SignCheckpointDigest signs the digest with the provider's private key.
func (p *staticKeyProvider) SignCheckpointDigest(digest []byte) ([]byte, error) {
	return ed25519.Sign(p.privateKey, digest), nil
}

// OutboxKey returns a copy of the AES-256 outbox key.
func (p *staticKeyProvider) OutboxKey() []byte {
	return append([]byte(nil), p.outboxKey...)
}

// GenerateOutboxKey returns 32 fresh bytes from crypto/rand for AES-256-GCM.
func GenerateOutboxKey() ([]byte, error) {
	key := make([]byte, outboxKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("witness outbox key: %w", err)
	}
	return key, nil
}

// PublicKeyFingerprint returns the lowercase hex SHA-256 over the raw Ed25519
// public key, or "" for an invalid key. It identifies a key without exporting it.
func PublicKeyFingerprint(publicKey ed25519.PublicKey) string {
	if len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:])
}
