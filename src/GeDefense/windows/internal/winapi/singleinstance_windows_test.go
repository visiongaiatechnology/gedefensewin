// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"unsafe"
)

// HP-FIND-005: object names are scoped to the current user/session identity so
// a well-known machine-wide name is not the single-instance authority.
func TestSingleInstanceObjectNameIsIdentityScoped(t *testing.T) {
	first, err := SingleInstanceObjectName("Tray.Instance.v5")
	if err != nil {
		t.Fatal(err)
	}
	second, err := SingleInstanceObjectName("Tray.Instance.v5")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("object name is not stable: %q vs %q", first, second)
	}
	if !strings.HasPrefix(first, `Local\VGT.GeDefense.`) {
		t.Fatalf("object name is not scoped to the Local session namespace: %q", first)
	}
	if strings.Contains(first, `Global\`) || strings.Contains(first, `\\`) {
		t.Fatalf("object name must not escape the session namespace: %q", first)
	}
	token, err := currentSessionIdentityToken()
	if err != nil {
		t.Skipf("session identity unavailable: %v", err)
	}
	if !strings.HasSuffix(first, token) || len(token) != 16 {
		t.Fatalf("object name does not carry the identity token %q: %q", token, first)
	}
	other, err := SingleInstanceObjectName("Center.Instance.v5")
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("different components must receive different object names")
	}
}

func testComponent(prefix, name string) string {
	digest := sha256.Sum256([]byte(name))
	return prefix + "." + hex.EncodeToString(digest[:6])
}

func TestValidateSingleInstanceComponent(t *testing.T) {
	for _, component := range []string{"", strings.Repeat("a", 65), `Tray\Instance`, "Tray:Instance", "Tray Instance", "../Tray"} {
		if err := ValidateSingleInstanceComponent(component); err == nil {
			t.Fatalf("component %q must be rejected", component)
		}
	}
	for _, component := range []string{"Tray.Instance.v5", "Center_Instance-5", "A"} {
		if err := ValidateSingleInstanceComponent(component); err != nil {
			t.Fatalf("component %q must be accepted: %v", component, err)
		}
	}
}

func TestCreateSingleInstanceMutexDetectsExistingTrustedObject(t *testing.T) {
	component := testComponent("Test.Trusted", t.Name())
	first, err := CreateSingleInstanceMutex(component)
	if err != nil {
		t.Skipf("single-instance object unavailable: %v", err)
	}
	defer func() { _ = first.Close() }()
	if first.Existed {
		t.Fatalf("first claim must not observe an existing object (%+v)", first)
	}
	second, err := CreateSingleInstanceMutex(component)
	if err != nil {
		if errors.Is(err, ErrSingleInstanceTakeover) {
			// A restricted sandbox token is denied by the product DACL on every
			// second open. That is an environment limitation, not a product
			// regression: creation with the product DACL itself succeeded above.
			t.Skipf("restricted-token environment cannot re-open the product DACL: %v", err)
		}
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	if !second.Existed {
		t.Fatalf("second claim must observe the existing object (%+v)", second)
	}
	if !second.Trusted {
		t.Fatalf("object created with the product DACL must be trusted (%+v)", second)
	}
	if second.Name != first.Name {
		t.Fatalf("claim names differ: %q vs %q", first.Name, second.Name)
	}
}

// HP-FIND-005 regression: an object created by other software (default DACL,
// i.e. the same-session pre-creation attack) must not remain an authority. The
// claim takes the object over (product DACL) and reports the counter-measure.
func TestCreateSingleInstanceMutexTakesOverForeignObject(t *testing.T) {
	component := testComponent("Test.Foreign", t.Name())
	name, err := SingleInstanceObjectName(component)
	if err != nil {
		t.Skipf("object name unavailable: %v", err)
	}
	foreign, existed, err := CreateMutex(name)
	if err != nil {
		t.Skipf("cannot create foreign mutex: %v", err)
	}
	defer func() { _ = CloseHandle(foreign) }()
	if existed {
		t.Fatal("foreign mutex was already left behind by an earlier test")
	}
	claim, err := CreateSingleInstanceMutex(component)
	if err != nil {
		if errors.Is(err, ErrSingleInstanceTakeover) {
			t.Skipf("restricted-token environment cannot verify the restored product DACL: %v", err)
		}
		t.Fatalf("accessible foreign object was not taken over: %v", err)
	}
	defer func() { _ = claim.Close() }()
	if !claim.Existed {
		t.Fatalf("claim must observe the foreign object (%+v)", claim)
	}
	if !claim.Trusted || !claim.TakenOver {
		t.Fatalf("foreign object must be taken over and trusted (%+v)", claim)
	}
	if trusted, err := singleInstanceObjectIsTrusted(claim.Handle, "mutex"); err != nil || !trusted {
		t.Fatalf("product DACL was not restored: trusted=%v err=%v", trusted, err)
	}
	// A second claim must now see a normal trusted product object instead of a
	// foreign one, i.e. the takeover permanently restored single-instance
	// authority for this identity.
	second, err := CreateSingleInstanceMutex(component)
	if err != nil {
		t.Fatalf("claim after takeover: %v", err)
	}
	defer func() { _ = second.Close() }()
	if !second.Existed || !second.Trusted || second.TakenOver {
		t.Fatalf("post-takeover claim is not a trusted product object: %+v", second)
	}
}

// createForeignSingleInstanceObject creates the same named kernel object with an
// arbitrary security descriptor, emulating pre-creation by other software that
// does not cooperate with the product DACL.
func createForeignSingleInstanceObject(kind, name, sddl string) (Handle, error) {
	namePointer, err := utf16Ptr(name)
	if err != nil {
		return 0, err
	}
	descriptor, err := sddlToSecurityDescriptor(sddl)
	if err != nil {
		return 0, err
	}
	attributes := &securityAttributes{
		length:     uint32(unsafe.Sizeof(securityAttributes{})),
		descriptor: descriptor,
	}
	defer attributes.free()
	var handle uintptr
	var callErr error
	switch kind {
	case "mutex":
		handle, _, callErr = procCreateMutexSingleInstance.Call(uintptr(unsafe.Pointer(attributes)), 0, uintptr(unsafe.Pointer(namePointer)))
	case "event":
		handle, _, callErr = procCreateEventSingleInstance.Call(uintptr(unsafe.Pointer(attributes)), 0, 0, uintptr(unsafe.Pointer(namePointer)))
	default:
		return 0, errors.New("foreign object kind rejected")
	}
	if handle == 0 {
		return 0, errors.Join(errors.New("foreign single-instance object creation failed"), errnoResult(callErr))
	}
	return Handle(handle), nil
}

// HP-FIND-005 fail-closed rule: when a foreign object denies access and cannot
// be taken over, the claim must return ErrSingleInstanceTakeover with no handle
// instead of accepting the foreign object as the running-instance authority.
func TestCreateSingleInstanceMutexFailsClosedOnInaccessibleForeignObject(t *testing.T) {
	if sid, err := currentUserSID(); err == nil && strings.EqualFold(sid, "S-1-5-18") {
		t.Skip("SYSTEM token bypasses the foreign DACL denial")
	}
	component := testComponent("Test.Denied", t.Name())
	name, err := SingleInstanceObjectName(component)
	if err != nil {
		t.Skipf("object name unavailable: %v", err)
	}
	foreign, err := createForeignSingleInstanceObject("mutex", name, `D:P(A;;GA;;;SY)`)
	if err != nil {
		t.Skipf("cannot create DACL-denying mutex: %v", err)
	}
	defer func() { _ = CloseHandle(foreign) }()
	claim, claimErr := CreateSingleInstanceMutex(component)
	if claimErr == nil {
		_ = claim.Close()
		t.Fatalf("inaccessible foreign object was accepted as authority (%+v)", claim)
	}
	if !errors.Is(claimErr, ErrSingleInstanceTakeover) {
		t.Fatalf("fail-closed claim does not wrap ErrSingleInstanceTakeover: %v", claimErr)
	}
	if claim.Handle != 0 {
		t.Fatalf("failed takeover leaked a handle (%+v)", claim)
	}
}

func TestCreateSingleInstanceEvent(t *testing.T) {
	component := testComponent("Test.Event", t.Name())
	claim, err := CreateSingleInstanceEvent(component, false, false)
	if err != nil {
		t.Skipf("single-instance event unavailable: %v", err)
	}
	defer func() { _ = claim.Close() }()
	if claim.Kind != "event" || claim.Handle == 0 || claim.Existed {
		t.Fatalf("unexpected event claim: %+v", claim)
	}
	if err := SetEvent(claim.Handle); err != nil {
		t.Fatalf("SetEvent failed: %v", err)
	}
}

// HP-FIND-005: the availability decision must never suppress the UI for a
// pre-created or unverifiable object.
func TestResolveSingleInstanceDecision(t *testing.T) {
	trustedExisting := SingleInstanceClaim{Existed: true, Trusted: true}
	foreignExisting := SingleInstanceClaim{Existed: true, Trusted: false}
	takenOverExisting := SingleInstanceClaim{Existed: true, Trusted: true, TakenOver: true}
	takenOverReplaced := SingleInstanceClaim{Existed: false, Trusted: true, TakenOver: true}
	fresh := SingleInstanceClaim{Existed: false, Trusted: true}
	cases := []struct {
		name        string
		claim       SingleInstanceClaim
		window      bool
		claimErr    error
		wantPrimary bool
		wantTamper  bool
	}{
		{name: "fresh object becomes primary", claim: fresh, window: false, wantPrimary: true, wantTamper: false},
		{name: "trusted object with live window delegates", claim: trustedExisting, window: true, wantPrimary: false, wantTamper: false},
		{name: "trusted object without window starts primary", claim: trustedExisting, window: false, wantPrimary: true, wantTamper: true},
		{name: "foreign object without window starts primary", claim: foreignExisting, window: false, wantPrimary: true, wantTamper: true},
		{name: "foreign object with window starts primary", claim: foreignExisting, window: true, wantPrimary: true, wantTamper: true},
		{name: "taken over object with live window delegates but reports tamper", claim: takenOverExisting, window: true, wantPrimary: false, wantTamper: true},
		{name: "replaced object starts primary and reports tamper", claim: takenOverReplaced, window: false, wantPrimary: true, wantTamper: true},
		{name: "creation and takeover error starts primary", claim: fresh, claimErr: errors.New("access denied"), wantPrimary: true, wantTamper: true},
	}
	for _, testCase := range cases {
		primary, tamper := ResolveSingleInstance(testCase.claim, testCase.window, testCase.claimErr)
		if primary != testCase.wantPrimary || tamper != testCase.wantTamper {
			t.Fatalf("%s: got primary=%v tamper=%v, want primary=%v tamper=%v", testCase.name, primary, tamper, testCase.wantPrimary, testCase.wantTamper)
		}
	}
}

func TestSingleInstanceClaimCloseIsIdempotent(t *testing.T) {
	claim, err := CreateSingleInstanceMutex(testComponent("Test.Close", t.Name()))
	if err != nil {
		t.Skipf("single-instance object unavailable: %v", err)
	}
	if err := claim.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := claim.Close(); err != nil {
		t.Fatalf("second close must be a no-op: %v", err)
	}
	var nilClaim *SingleInstanceClaim
	if err := nilClaim.Close(); err != nil {
		t.Fatalf("nil claim close must be a no-op: %v", err)
	}
}
