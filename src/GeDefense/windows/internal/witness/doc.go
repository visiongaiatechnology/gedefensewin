// STATUS: PLATIN VGT SUPREME

// Package witness implements the GeDefense Windows V6 out-of-band witness
// client. It is a pure-Go, dependency-free, Windows-ready package that turns an
// authenticated evidence ledger head into a signed checkpoint, queues it in an
// AEAD-protected crash-safe outbox and pushes it to an external witness over a
// hardened HTTPS channel. An air-gap token format (vgtw1:) covers deployments
// without a network path.
//
// The package is deliberately self-contained: it imports no other GeDefense
// package and therefore cannot create import cycles. The application wires the
// evidence ledger through the narrow LedgerSource interface; the signing and
// outbox keys are supplied through KeyProvider. Nothing is global: every
// goroutine is owned by Engine and joined on Close.
//
// Design rules enforced here:
//
//   - fail closed: invalid settings, unknown JSON, a corrupt outbox, a ledger
//     rollback or a pin mismatch produce an error or the FAULT state, never a
//     silent fallback;
//   - bounded resources: response bodies (1 MiB), checkpoint documents
//     (64 KiB), outbox entries (1024) and outbox bytes (4 MiB) all have hard
//     upper bounds;
//   - constant time: SPKI pins, checkpoint digests and key fingerprints are
//     compared with crypto/subtle, signatures with ed25519.Verify;
//   - crypto/rand only, no math/rand, no insecure TLS, no panics in library
//     code, no logging of endpoints, paths or key material.
//
// Status vocabulary of Engine.Status is exactly DISABLED, UNVERIFIED,
// CONNECTED, DEGRADED and FAULT; see engine.go for the transition contract.
package witness
