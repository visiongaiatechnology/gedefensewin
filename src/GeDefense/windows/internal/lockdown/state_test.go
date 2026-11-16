// STATUS: PLATIN VGT SUPREME

package lockdown

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStateStoreRoundTrip(t *testing.T) {
	clock := newFakeClock()
	store, path := newTestStore(t)
	document := sampleLatchedDocument(clock)
	if err := store.Save(document); err != nil {
		t.Fatalf("save: %v", err)
	}
	if store.Path() != path {
		t.Fatalf("unexpected store path: %q", store.Path())
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Schema != document.Schema || loaded.State != document.State || !loaded.Latched {
		t.Fatalf("document metadata changed in the round-trip: %+v", loaded)
	}
	if loaded.Epoch != document.Epoch || !loaded.UpdatedAt.Equal(document.UpdatedAt) {
		t.Fatalf("document bookkeeping changed in the round-trip: %+v", loaded)
	}
	if loaded.Trigger != document.Trigger {
		t.Fatalf("trigger changed in the round-trip: %+v", loaded.Trigger)
	}
	if len(loaded.Phases) != 1 || loaded.Phases[0].Phase != PhaseUSB || loaded.Phases[0].Status != PhaseApplied {
		t.Fatalf("phase results changed in the round-trip: %+v", loaded.Phases)
	}
	// The envelope must be authenticated and must not leak the plaintext.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	if len(raw) <= stateHeaderBytes+stateNonceBytes {
		t.Fatalf("the sealed document is implausibly short: %d bytes", len(raw))
	}
	if !bytes.Equal(raw[:4], stateMagic[:]) {
		t.Fatalf("the state magic is missing: %x", raw[:4])
	}
	if raw[4] != stateVersion {
		t.Fatalf("unexpected state version: %d", raw[4])
	}
	if bytes.Contains(raw, []byte(stateSchema)) || bytes.Contains(raw, []byte("trig-1")) {
		t.Fatal("the state document was not sealed: plaintext is visible")
	}
}

func TestStateStoreTamperFailsAuthentication(t *testing.T) {
	clock := newFakeClock()
	store, path := newTestStore(t)
	if err := store.Save(sampleLatchedDocument(clock)); err != nil {
		t.Fatalf("save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)/2] ^= 0x01
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered state: %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("a tampered document was accepted: %v", err)
	}
	// A flipped header byte is rejected as well.
	headerTampered := append([]byte(nil), raw...)
	headerTampered[5] = 0xff
	if err := os.WriteFile(path, headerTampered, 0o600); err != nil {
		t.Fatalf("write header tampered state: %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("a tampered header was accepted: %v", err)
	}
}

func TestStateStoreWrongKeyIsRejected(t *testing.T) {
	clock := newFakeClock()
	store, path := newTestStore(t)
	if err := store.Save(sampleLatchedDocument(clock)); err != nil {
		t.Fatalf("save: %v", err)
	}
	otherKey := make([]byte, stateKeyBytes)
	for index := range otherKey {
		otherKey[index] = byte(255 - index)
	}
	otherStore, err := NewStateStore(path, StaticKeyProvider(otherKey))
	if err != nil {
		t.Fatalf("other store: %v", err)
	}
	if _, err := otherStore.Load(); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("a document sealed with another key was accepted: %v", err)
	}
}

func TestStateStoreMissingFileIsFirstStart(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Load(); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("a missing document was not reported as first start: %v", err)
	}
}

func TestStateStoreRejectsInvalidKeyAndPath(t *testing.T) {
	if _, err := NewStateStore("relative.state", testKey()); !errors.Is(err, ErrStatePathInvalid) {
		t.Fatalf("a relative path was accepted: %v", err)
	}
	if _, err := NewStateStore("", testKey()); !errors.Is(err, ErrStatePathInvalid) {
		t.Fatalf("an empty path was accepted: %v", err)
	}
	if _, err := NewStateStore(`C:\`, testKey()); !errors.Is(err, ErrStatePathInvalid) {
		t.Fatalf("a directory path was accepted: %v", err)
	}
	shortKey := make([]byte, 16)
	if _, err := NewStateStore(`C:\state`, StaticKeyProvider(shortKey)); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("a short key was accepted: %v", err)
	}
	if _, err := NewStateStore(`C:\state`, nil); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("a nil key provider was accepted: %v", err)
	}
}

func TestStateStoreRejectsOversizedDocument(t *testing.T) {
	store, path := newTestStore(t)
	oversized := make([]byte, StateMaxFileBytes+1)
	if err := os.WriteFile(path, oversized, 0o600); err != nil {
		t.Fatalf("write oversized state: %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrStateTooLarge) {
		t.Fatalf("an oversized document was accepted: %v", err)
	}
}

func TestStateStoreUsesFreshNonce(t *testing.T) {
	clock := newFakeClock()
	store, path := newTestStore(t)
	document := sampleLatchedDocument(clock)
	if err := store.Save(document); err != nil {
		t.Fatalf("first save: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}
	if err := store.Save(document); err != nil {
		t.Fatalf("second save: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two seals produced the same bytes; the nonce is not fresh")
	}
}

func TestStateStoreRefusesInvalidDocument(t *testing.T) {
	store, _ := newTestStore(t)
	document := sampleLatchedDocument(newFakeClock())
	document.State = StateEngaging
	if err := store.Save(document); err == nil {
		t.Fatal("an invalid document was persisted")
	}
}

func TestDecodeStateDocumentIsStrict(t *testing.T) {
	clock := newFakeClock()
	valid := sampleLatchedDocument(clock)
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	generic["unexpected_field"] = true
	withUnknown, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("marshal unknown field: %v", err)
	}
	if _, err := decodeStateDocument(withUnknown); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("an unknown JSON field was accepted: %v", err)
	}
	if _, err := decodeStateDocument([]byte("not-json")); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("invalid JSON was accepted: %v", err)
	}
}

func TestValidateStateDocumentMatrix(t *testing.T) {
	clock := newFakeClock()
	valid := sampleLatchedDocument(clock)
	cases := map[string]func(*stateDocument){
		"wrong-schema":       func(d *stateDocument) { d.Schema = "v1" },
		"zero-revision":      func(d *stateDocument) { d.Revision = 0 },
		"unknown-state":      func(d *stateDocument) { d.State = "OFF" },
		"engaging-persisted": func(d *stateDocument) { d.State = StateEngaging },
		"latched-clear":      func(d *stateDocument) { d.State = StateClear; d.Latched = true },
		"clear-with-epoch":   func(d *stateDocument) { d.State = StateClear; d.Latched = false },
		"bad-epoch":          func(d *stateDocument) { d.Epoch = "0BADCODE" },
		"short-epoch":        func(d *stateDocument) { d.Epoch = "abc" },
		"missing-trigger":    func(d *stateDocument) { d.Trigger = Trigger{} },
		"missing-engage":     func(d *stateDocument) { d.EngagedAt = time.Time{} },
		"missing-updated":    func(d *stateDocument) { d.UpdatedAt = time.Time{} },
		"unknown-transition": func(d *stateDocument) { d.Transition = "paused" },
		"unknown-action":     func(d *stateDocument) { d.Action = "arm" },
		"bad-phase": func(d *stateDocument) {
			d.Phases = []PhaseResult{{Action: ActionEngage, Phase: "RULES", Status: PhaseApplied}}
		},
		"bad-phase-status": func(d *stateDocument) {
			d.Phases = []PhaseResult{{Action: ActionEngage, Phase: PhaseUSB, Status: "locked"}}
		},
		"too-many-phases": func(d *stateDocument) {
			d.Phases = make([]PhaseResult, len(phaseSequence)+1)
		},
		"bad-clear-record": func(d *stateDocument) { d.LastClear = &ClearRecord{Reason: "x"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			document := valid
			document.Phases = append([]PhaseResult(nil), valid.Phases...)
			mutate(&document)
			if err := validateStateDocument(&document); !errors.Is(err, ErrStateCorrupt) {
				t.Fatalf("an invalid document validated: %v", err)
			}
		})
	}
	if err := validateStateDocument(&valid); err != nil {
		t.Fatalf("the valid document was rejected: %v", err)
	}
}

func TestRecoverStateDocumentCrashWindows(t *testing.T) {
	clock := newFakeClock()
	for name, transition := range map[string]string{
		"interrupted-engage": transitionEngaging,
		"interrupted-clear":  transitionClearing,
	} {
		t.Run(name, func(t *testing.T) {
			document := sampleLatchedDocument(clock)
			document.Transition = transition
			recovered, changed := recoverStateDocument(document)
			if !changed {
				t.Fatal("the crash window was not recovered")
			}
			if recovered.State != StateEngaged || !recovered.Latched {
				t.Fatalf("the crash window was not recovered fail-closed: %+v", recovered)
			}
			if !recovered.NeedsVerification {
				t.Fatal("the recovered latch does not require verification")
			}
			if recovered.Transition != "" {
				t.Fatalf("the transition marker survived recovery: %q", recovered.Transition)
			}
			if !strings.Contains(recovered.LastError, "interrupted") {
				t.Fatalf("the recovery reason is missing: %q", recovered.LastError)
			}
			if err := validateStateDocument(&recovered); err != nil {
				t.Fatalf("the recovered document is invalid: %v", err)
			}
		})
	}
	document := sampleLatchedDocument(clock)
	if _, changed := recoverStateDocument(document); changed {
		t.Fatal("a clean document was reported as a crash window")
	}
}
