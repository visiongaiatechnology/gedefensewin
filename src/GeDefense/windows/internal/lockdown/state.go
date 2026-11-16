// STATUS: PLATIN VGT SUPREME

package lockdown

// The lockdown latch is one authenticated, atomically written document
// (lockdown-engine.state).
//
// Envelope: a 4-byte magic, a 1-byte version and 3 reserved zero bytes, then a
// fresh 12-byte crypto/rand nonce and the AES-256-GCM ciphertext. The AAD binds
// the versioned schema and the version byte, so a document copied under another
// schema/version purpose fails authentication. The key comes from an injected
// KeyProvider and must be exactly 32 bytes.
//
// Writes are crash-safe: the sealed document is written to a temporary file in
// the same directory, flushed, fsynced, closed and renamed over the previous
// file. The bounded plaintext (<= 32 KiB) and the bounded file (<= 64 KiB) are
// checked before anything is written or decoded.
//
// A document that does not authenticate or does not validate never releases the
// latch: the engine latches fail-closed and reports the degraded recovery.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// StateFileName is the documented state document name.
	StateFileName = "lockdown-engine.state"
	// stateSchema versions the plaintext document.
	stateSchema = "vgt-gedefense-lockdown-engine-v1"
	// stateAADPrefix binds the AEAD envelope to this store and schema.
	stateAADPrefix = "vgt-gedefense-lockdown-engine-v1"
	// stateKeyBytes is the required AES-256 key size.
	stateKeyBytes = 32
	// stateNonceBytes is the required GCM nonce size.
	stateNonceBytes = 12
	// stateHeaderBytes is magic(4) + version(1) + reserved(3).
	stateHeaderBytes = 8
	// StateMaxFileBytes bounds the sealed document (64 KiB, like Linux).
	StateMaxFileBytes = int64(64 << 10)
	// stateMaxPlaintextBytes bounds the decoded plaintext.
	stateMaxPlaintextBytes = int64(32 << 10)
	// stateMaxPathBytes bounds the state path.
	stateMaxPathBytes = 4096
)

var (
	stateMagic   = [4]byte{'V', 'G', 'L', 'S'}
	stateVersion = byte(1)
)

// Transition markers persisted during a crash window. A document found with one
// of them is recovered fail-closed by recoverStateDocument.
const (
	transitionEngaging = "engaging"
	transitionClearing = "clearing"
)

// EngineState is the closed status vocabulary of the engine.
type EngineState string

const (
	// StateClear is the disarmed state: no latch is held.
	StateClear EngineState = "CLEAR"
	// StateEngaged is the latched state: at least one phase reported an applied
	// or partial isolation.
	StateEngaged EngineState = "ENGAGED"
	// StateEngaging is the transition marker while phases run.
	StateEngaging EngineState = "ENGAGING"
	// StateFailed is the latched state in which no phase reported an applied or
	// partial isolation. The latch is still held (fail-closed); the status never
	// claims "locked".
	StateFailed EngineState = "FAILED"
	// StateDisabled is the disarmed state of an engine whose namespace is
	// disabled. It is never reported while a latch is held.
	StateDisabled EngineState = "DISABLED"
)

// Valid reports whether s is in the closed vocabulary.
func (s EngineState) Valid() bool {
	switch s {
	case StateClear, StateEngaged, StateEngaging, StateFailed, StateDisabled:
		return true
	}
	return false
}

// persistedStateValid reports whether s may appear in the persisted document.
func persistedStateValid(s EngineState) bool {
	return s == StateClear || s == StateEngaged || s == StateFailed
}

// ClearRecord is the bounded record of the last successful clear.
type ClearRecord struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
	Epoch  string    `json:"epoch,omitempty"`
}

// KeyProvider supplies the 32-byte AES-256-GCM key of the state document. It is
// injected so the engine never owns key material itself.
type KeyProvider interface {
	Key() ([]byte, error)
}

// StaticKeyProvider is a KeyProvider over a caller-owned key. It is intended for
// tests and for callers that load the key through the evidence secret store. The
// key is copied; the provider never returns its internal slice.
type StaticKeyProvider []byte

// Key returns a copy of the configured key.
func (p StaticKeyProvider) Key() ([]byte, error) {
	out := make([]byte, len(p))
	copy(out, p)
	return out, nil
}

// stateDocument is the persisted latch document. It carries only
// operator-relevant facts: no path, no command line, no secret.
type stateDocument struct {
	Schema            string        `json:"schema"`
	Revision          uint64        `json:"revision"`
	State             EngineState   `json:"state"`
	Latched           bool          `json:"latched"`
	Epoch             string        `json:"epoch,omitempty"`
	EngagedAt         time.Time     `json:"engaged_at,omitempty"`
	ClearedAt         time.Time     `json:"cleared_at,omitempty"`
	Trigger           Trigger       `json:"trigger"`
	Action            PhaseAction   `json:"action,omitempty"`
	Phases            []PhaseResult `json:"phases,omitempty"`
	Transition        string        `json:"transition,omitempty"`
	NeedsVerification bool          `json:"needs_verification,omitempty"`
	VerifiedAt        time.Time     `json:"verified_at,omitempty"`
	LastClear         *ClearRecord  `json:"last_clear,omitempty"`
	LastError         string        `json:"last_error,omitempty"`
	Degraded          string        `json:"degraded,omitempty"`
	UpdatedAt         time.Time     `json:"updated_at"`
}

// StateStore owns the sealed latch document. It is safe for concurrent use by
// the engine's serialised transitions.
type StateStore struct {
	path string
	aead cipher.AEAD
}

// NewStateStore validates the path and the key and returns the store. A key
// provider failure, a wrong key size or a relative path is refused at
// construction: there is no plaintext fallback.
func NewStateStore(path string, provider KeyProvider) (*StateStore, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: a key provider is required", ErrKeyInvalid)
	}
	if path == "" || len(path) > stateMaxPathBytes || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: the state path must be absolute and bounded", ErrStatePathInvalid)
	}
	cleaned := filepath.Clean(path)
	if filepath.Base(cleaned) == "." || filepath.Dir(cleaned) == cleaned {
		return nil, fmt.Errorf("%w: the state path must name a file", ErrStatePathInvalid)
	}
	key, err := provider.Key()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}
	if len(key) != stateKeyBytes {
		return nil, fmt.Errorf("%w: the key must be %d bytes, got %d", ErrKeyInvalid, stateKeyBytes, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}
	if aead.NonceSize() != stateNonceBytes {
		return nil, fmt.Errorf("%w: unexpected GCM nonce size", ErrKeyInvalid)
	}
	return &StateStore{path: cleaned, aead: aead}, nil
}

// Path returns the configured document path.
func (s *StateStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// stateAAD builds the versioned additional authenticated data.
func stateAAD() []byte {
	aad := make([]byte, 0, len(stateAADPrefix)+1)
	aad = append(aad, stateAADPrefix...)
	aad = append(aad, stateVersion)
	return aad
}

// Load reads, authenticates, decodes and validates the document. A missing
// document is the documented first start and returns ErrStateNotFound.
func (s *StateStore) Load() (stateDocument, error) {
	if s == nil || s.aead == nil {
		return stateDocument{}, fmt.Errorf("%w: state store is not initialised", ErrStateCorrupt)
	}
	info, err := os.Lstat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return stateDocument{}, fmt.Errorf("%w: %v", ErrStateNotFound, err)
	}
	if err != nil {
		return stateDocument{}, fmt.Errorf("%w: the document is unreadable: %v", ErrStateCorrupt, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return stateDocument{}, fmt.Errorf("%w: the document must be a regular file", ErrStateCorrupt)
	}
	if info.Size() <= 0 || info.Size() > StateMaxFileBytes {
		return stateDocument{}, fmt.Errorf("%w: the document size is outside its bound", ErrStateTooLarge)
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return stateDocument{}, fmt.Errorf("%w: the document is unreadable: %v", ErrStateCorrupt, err)
	}
	if int64(len(raw)) > StateMaxFileBytes {
		return stateDocument{}, fmt.Errorf("%w: the document size is outside its bound", ErrStateTooLarge)
	}
	plaintext, err := s.open(raw)
	if err != nil {
		return stateDocument{}, err
	}
	document, err := decodeStateDocument(plaintext)
	if err != nil {
		return stateDocument{}, err
	}
	return document, nil
}

// open authenticates one sealed document and returns its plaintext.
func (s *StateStore) open(raw []byte) ([]byte, error) {
	if len(raw) < stateHeaderBytes+stateNonceBytes+s.aead.Overhead() {
		return nil, fmt.Errorf("%w: the document is truncated", ErrStateCorrupt)
	}
	if !bytes.Equal(raw[:4], stateMagic[:]) {
		return nil, fmt.Errorf("%w: the magic does not match", ErrStateCorrupt)
	}
	if raw[4] != stateVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrStateCorrupt, raw[4])
	}
	if raw[5] != 0 || raw[6] != 0 || raw[7] != 0 {
		return nil, fmt.Errorf("%w: the reserved header bytes are not zero", ErrStateCorrupt)
	}
	nonce := raw[stateHeaderBytes : stateHeaderBytes+stateNonceBytes]
	ciphertext := raw[stateHeaderBytes+stateNonceBytes:]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, stateAAD())
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", ErrStateCorrupt)
	}
	if int64(len(plaintext)) > stateMaxPlaintextBytes {
		return nil, fmt.Errorf("%w: the plaintext is outside its bound", ErrStateTooLarge)
	}
	return plaintext, nil
}

// decodeStateDocument strictly decodes and validates one plaintext document.
func decodeStateDocument(plaintext []byte) (stateDocument, error) {
	var document stateDocument
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return stateDocument{}, fmt.Errorf("%w: the document is not valid JSON in the expected schema", ErrStateCorrupt)
	}
	if err := validateStateDocument(&document); err != nil {
		return stateDocument{}, err
	}
	return document, nil
}

// validateStateDocument rejects every structurally invalid document. It is the
// gate that turns a tampered-but-authentic document (for example one written by
// a future or buggy build) into a fail-closed recovery instead of a state
// transition.
func validateStateDocument(document *stateDocument) error {
	if document == nil {
		return fmt.Errorf("%w: the document is missing", ErrStateCorrupt)
	}
	if document.Schema != stateSchema {
		return fmt.Errorf("%w: the schema is unknown", ErrStateCorrupt)
	}
	if document.Revision == 0 {
		return fmt.Errorf("%w: the revision is zero", ErrStateCorrupt)
	}
	if !persistedStateValid(document.State) {
		return fmt.Errorf("%w: the state is not in the persisted vocabulary", ErrStateCorrupt)
	}
	if document.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: the update time is missing", ErrStateCorrupt)
	}
	if document.Epoch != "" && !validEpoch(document.Epoch) {
		return fmt.Errorf("%w: the epoch is not eight lowercase hex characters", ErrStateCorrupt)
	}
	if document.Latched {
		if document.State != StateEngaged && document.State != StateFailed {
			return fmt.Errorf("%w: a latched document is not engaged", ErrStateCorrupt)
		}
		if !validEpoch(document.Epoch) {
			return fmt.Errorf("%w: a latched document requires a valid epoch", ErrStateCorrupt)
		}
		if document.EngagedAt.IsZero() {
			return fmt.Errorf("%w: a latched document requires an engage time", ErrStateCorrupt)
		}
		if err := document.Trigger.Validate(); err != nil {
			return fmt.Errorf("%w: the trigger is invalid: %v", ErrStateCorrupt, err)
		}
	} else {
		if document.State != StateClear {
			return fmt.Errorf("%w: an unlatched document must be CLEAR", ErrStateCorrupt)
		}
		if document.Epoch != "" {
			return fmt.Errorf("%w: an unlatched document must not carry an epoch", ErrStateCorrupt)
		}
		if document.Trigger != (Trigger{}) {
			return fmt.Errorf("%w: an unlatched document must not carry a trigger", ErrStateCorrupt)
		}
	}
	switch document.Transition {
	case "", transitionEngaging, transitionClearing:
	default:
		return fmt.Errorf("%w: the transition marker is unknown", ErrStateCorrupt)
	}
	if document.Action != "" && document.Action != ActionEngage && document.Action != ActionRelease {
		return fmt.Errorf("%w: the action marker is unknown", ErrStateCorrupt)
	}
	if len(document.Phases) > len(phaseSequence) {
		return fmt.Errorf("%w: the phase list exceeds its bound", ErrStateCorrupt)
	}
	for index := range document.Phases {
		if err := validatePhaseResult(document.Phases[index]); err != nil {
			return fmt.Errorf("%w: phase result %d is invalid: %v", ErrStateCorrupt, index, err)
		}
	}
	if document.LastClear != nil {
		if document.LastClear.At.IsZero() {
			return fmt.Errorf("%w: the last clear time is missing", ErrStateCorrupt)
		}
		if len(document.LastClear.Reason) > MaxReasonBytes {
			return fmt.Errorf("%w: the last clear reason is out of bounds", ErrStateCorrupt)
		}
		if document.LastClear.Epoch != "" && !validEpoch(document.LastClear.Epoch) {
			return fmt.Errorf("%w: the last clear epoch is invalid", ErrStateCorrupt)
		}
	}
	if len(document.LastError) > MaxDetailBytes*4 || len(document.Degraded) > MaxDetailBytes*4 {
		return fmt.Errorf("%w: a detail string exceeds its bound", ErrStateCorrupt)
	}
	return nil
}

// recoverStateDocument maps a crash window onto the fail-closed direction:
// an interrupted engage or clear is recovered as latched ENGAGED that needs
// verification. It returns the recovered document and whether anything changed.
func recoverStateDocument(document stateDocument) (stateDocument, bool) {
	recovered := false
	switch document.Transition {
	case transitionEngaging:
		document.State = StateEngaged
		document.Latched = true
		document.NeedsVerification = true
		document.LastError = truncateText("interrupted engage recovered as ENGAGED; isolation was not verified: "+document.LastError, MaxDetailBytes*2)
		recovered = true
	case transitionClearing:
		document.State = StateEngaged
		document.Latched = true
		document.NeedsVerification = true
		document.LastError = truncateText("interrupted clear recovered fail-closed; the release was not confirmed: "+document.LastError, MaxDetailBytes*2)
		recovered = true
	}
	if document.Latched && document.State != StateEngaged && document.State != StateFailed {
		document.State = StateEngaged
		document.Latched = true
		document.NeedsVerification = true
		recovered = true
	}
	if recovered {
		document.Transition = ""
	}
	return document, recovered
}

// Save validates the document, seals it and writes it crash-safely. A failed or
// interrupted write leaves the previous document in force.
func (s *StateStore) Save(document stateDocument) error {
	if s == nil || s.aead == nil {
		return fmt.Errorf("%w: state store is not initialised", ErrStateCorrupt)
	}
	if err := validateStateDocument(&document); err != nil {
		return fmt.Errorf("refusing to persist an invalid document: %w", err)
	}
	plaintext, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("lockdown state encoding: %w", err)
	}
	if int64(len(plaintext)) > stateMaxPlaintextBytes {
		return fmt.Errorf("%w: the plaintext exceeds its bound", ErrStateTooLarge)
	}
	sealed, err := s.seal(plaintext)
	if err != nil {
		return err
	}
	if int64(len(sealed)) > StateMaxFileBytes {
		return fmt.Errorf("%w: the sealed document exceeds its bound", ErrStateTooLarge)
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("lockdown state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".lockdown-engine-*.tmp")
	if err != nil {
		return fmt.Errorf("lockdown state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := temporary.Write(sealed); err != nil {
		return fmt.Errorf("lockdown state write: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("lockdown state flush: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("lockdown state close: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("lockdown state replace: %w", err)
	}
	cleanup = false
	return nil
}

// seal encodes the envelope with a fresh crypto/rand nonce.
func (s *StateStore) seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, stateNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("lockdown state nonce: %w", err)
	}
	sealed := make([]byte, 0, stateHeaderBytes+stateNonceBytes+len(plaintext)+s.aead.Overhead())
	sealed = append(sealed, stateMagic[:]...)
	sealed = append(sealed, stateVersion, 0, 0, 0)
	sealed = append(sealed, nonce...)
	return s.aead.Seal(sealed, nonce, plaintext, stateAAD()), nil
}

// validEpoch reports the canonical 8 lowercase hex character epoch.
func validEpoch(epoch string) bool {
	if len(epoch) != 8 {
		return false
	}
	for _, char := range epoch {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// epochEqual compares two epochs in constant time.
func epochEqual(expected, actual string) bool {
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

// newEpoch mints the 8-hex compare-set token. The epoch is not a secret; it only
// has to be unique and unpredictable enough to prevent a stale clear. A
// crypto/rand failure therefore falls back to a SHA-256 derived value instead of
// leaving the latch without an epoch.
func newEpoch(clock Clock) string {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err == nil {
		candidate := hex.EncodeToString(raw[:])
		if candidate != "00000000" {
			return candidate
		}
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("lockdown-epoch:%d:%s", clock.Now().UnixNano(), clockNonce())))
	return hex.EncodeToString(digest[:4])
}

// clockNonce returns a bounded, best-effort varying suffix for the epoch
// fallback. It reuses the crypto/rand source and degrades to the clock only.
func clockNonce() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return "fallback"
}

// appendDetail joins a bounded detail without growing without bound.
func appendDetail(detail, addition string) string {
	detail = strings.TrimSpace(detail)
	addition = strings.TrimSpace(addition)
	if detail == "" {
		return truncateText(addition, MaxDetailBytes*2)
	}
	if addition == "" {
		return truncateText(detail, MaxDetailBytes*2)
	}
	return truncateText(detail+"; "+addition, MaxDetailBytes*2)
}
