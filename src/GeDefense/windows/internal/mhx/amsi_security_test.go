// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// TestAmsiLocalModuleIdentityAndOffset proves the on-disk PE export RVA and the
// LoadLibrary-derived offset describe the same native amsi.dll image; a mismatch
// would mean the service loaded a foreign copy and every scan would be
// unverified (fail-closed by design).
func TestAmsiLocalModuleIdentityAndOffset(t *testing.T) {
	path, size, err := localAmsiModuleIdentity()
	if err != nil {
		t.Fatalf("local amsi.dll identity unavailable: %v", err)
	}
	if size == 0 || !strings.HasSuffix(strings.ToLower(path), `\amsi.dll`) {
		t.Fatalf("invalid local amsi identity: path=%q size=%d", path, size)
	}
	offset := getAmsiScanBufferOffset()
	if offset == 0 {
		t.Fatalf("AmsiScanBuffer offset must be resolved from %s", path)
	}
	identity, err := amsiImageIdentityFor(false)
	if err != nil {
		t.Fatalf("native amsi identity unavailable: %v", err)
	}
	if identity.exportRVA == 0 || identity.exportRVA >= identity.size {
		t.Fatalf("implausible AmsiScanBuffer export RVA %d (SizeOfImage %d)", identity.exportRVA, identity.size)
	}
	if uint32(offset) != identity.exportRVA {
		t.Fatalf("LoadLibrary offset %d and PE export RVA %d disagree", offset, identity.exportRVA)
	}
}

func TestAmsiWow64Identity(t *testing.T) {
	identity, err := amsiImageIdentityFor(true)
	if err != nil {
		t.Skipf("WOW64 amsi.dll unavailable: %v", err)
	}
	if !identity.wow64 {
		t.Fatal("wow64 identity is not flagged as WOW64")
	}
	lower := strings.ToLower(identity.path)
	if !strings.HasSuffix(lower, `\syswow64\amsi.dll`) {
		t.Fatalf("WOW64 identity path = %q, want a SysWOW64 path", identity.path)
	}
	if identity.size == 0 || identity.exportRVA == 0 || identity.exportRVA >= identity.size {
		t.Fatalf("implausible WOW64 identity: size=%d exportRVA=%d", identity.size, identity.exportRVA)
	}
}

func TestAmsiScanRejectsInvalidInputs(t *testing.T) {
	// The historical boundary contract: reserved PIDs and a zero offset are
	// no-ops and never touch a handle.
	if patched, err := isAmsiPatched(ProcessEvent{PID: 0}, 1); patched || err != nil {
		t.Fatalf("pid 0 must be rejected without error, got patched=%v err=%v", patched, err)
	}
	if patched, err := isAmsiPatched(ProcessEvent{PID: 4}, 1); patched || err != nil {
		t.Fatalf("pid 4 must be rejected without error, got patched=%v err=%v", patched, err)
	}
	if patched, err := isAmsiPatched(ProcessEvent{PID: 100}, 0); patched || err != nil {
		t.Fatalf("zero offset must be a no-op, got patched=%v err=%v", patched, err)
	}
}

// TestAmsiScanRejectsPIDReuseIdentityMismatch simulates PID reuse: the PID is
// alive but the event's creation time / image path describe a different
// process. The hardened identity gate must reject the scan with an error instead
// of scanning (and potentially striking) the live process.
func TestAmsiScanRejectsPIDReuseIdentityMismatch(t *testing.T) {
	identity, err := winapi.OpenProcessIdentity(uint32(os.Getpid()), false)
	if err != nil {
		t.Skipf("cannot query own process identity: %v", err)
	}
	executable := identity.ImagePath
	if executable == "" {
		t.Skip("own process image path unavailable")
	}
	_ = identity.Close()

	if patched, err := isAmsiPatched(ProcessEvent{
		PID:         uint32(os.Getpid()),
		CreationUTC: time.Now().UTC().Add(-24 * time.Hour),
		ImagePath:   executable,
		Image:       filepath.Base(executable),
	}, 1); err == nil || patched {
		t.Fatalf("wrong creation time must fail closed, got patched=%v err=%v", patched, err)
	}

	actual, err := winapi.OpenProcessIdentity(uint32(os.Getpid()), false)
	if err != nil {
		t.Skipf("cannot query own process identity: %v", err)
	}
	creation := time.Unix(0, actual.CreationUnixNano).UTC()
	_ = actual.Close()
	if patched, err := isAmsiPatched(ProcessEvent{
		PID:         uint32(os.Getpid()),
		CreationUTC: creation,
		ImagePath:   `C:\Windows\System32\notepad.exe`,
		Image:       "notepad.exe",
	}, 1); err == nil || patched {
		t.Fatalf("wrong image path must fail closed, got patched=%v err=%v", patched, err)
	}
}

func TestAmsiProloguePatterns(t *testing.T) {
	cases := []struct {
		name    string
		window  []byte
		patched bool
	}{
		{"clean-64bit-prologue", []byte{0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49, 0x89, 0x6B, 0x10}, false},
		{"clean-32bit-prologue", []byte{0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20}, false},
		{"classic-e57", []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3, 0x90, 0x90}, true},
		{"access-denied", []byte{0xB8, 0x05, 0x00, 0x07, 0x80, 0xC3}, true},
		{"xor-eax-ret", []byte{0x31, 0xC0, 0xC3}, true},
		{"xor-rax-ret", []byte{0x48, 0x31, 0xC0, 0xC3}, true},
		{"mov-rax-zero", []byte{0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3}, true},
		{"ret", []byte{0xC3, 0x90}, true},
		{"jmp-short", []byte{0xEB, 0x05, 0x90}, true},
		{"jmp-near", []byte{0xE9, 0x00, 0x10, 0x00, 0x00}, true},
		{"mov-eax-imm-ret", []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0x90, 0xC3}, true},
		{"empty", nil, false},
		{"one-byte", []byte{0x90}, false},
	}
	for _, testCase := range cases {
		if got := isAmsiProloguePatched(testCase.window); got != testCase.patched {
			t.Fatalf("%s: isAmsiProloguePatched(%x) = %v, want %v", testCase.name, testCase.window, got, testCase.patched)
		}
	}
	// The classic patch is only detected at the entry point, not somewhere in
	// the middle of the bounded window.
	padded := append([]byte{0x4C, 0x8B, 0xDC}, []byte{0xB8, 0x57, 0x00, 0x07, 0x80}...)
	if isAmsiProloguePatched(padded) {
		t.Fatal("patch pattern in the middle of the window must not match the entry")
	}
}

func TestAmsiScanWindowBounds(t *testing.T) {
	if _, err := amsiScanWindowLength(0, 0); err == nil {
		t.Fatal("zero module size must be rejected")
	}
	if _, err := amsiScanWindowLength(100, 100); err == nil {
		t.Fatal("offset outside the module must be rejected")
	}
	if _, err := amsiScanWindowLength(100, 95); err == nil {
		t.Fatal("a window smaller than the minimum must be rejected")
	}
	length, err := amsiScanWindowLength(4096, 0)
	if err != nil || length != amsiPrologueWindowBytes {
		t.Fatalf("full window = %d/%v, want %d", length, err, amsiPrologueWindowBytes)
	}
	length, err = amsiScanWindowLength(100, 90)
	if err != nil || length != 10 {
		t.Fatalf("clamped window = %d/%v, want 10", length, err)
	}
}

func TestAmsiModulePathClassification(t *testing.T) {
	root := triageSystemRoot()
	wow64, err := classifyAmsiModulePath(root + `\SysWOW64\amsi.dll`)
	if err != nil || !wow64 {
		t.Fatalf("SysWOW64 amsi.dll must classify as WOW64, got wow64=%v err=%v", wow64, err)
	}
	native, err := classifyAmsiModulePath(root + `\System32\amsi.dll`)
	if err != nil || native {
		t.Fatalf("System32 amsi.dll must classify as native, got wow64=%v err=%v", native, err)
	}
	// Case-insensitive canonical form is accepted.
	if _, err := classifyAmsiModulePath(strings.ToUpper(root + `\System32\amsi.dll`)); err != nil {
		t.Fatalf("case-insensitive canonical path rejected: %v", err)
	}
	for _, bad := range []string{
		"",
		`C:\Users\Public\amsi.dll`,
		root + `\System32\amsi.dll.bak`,
		root + `\System32\evil\amsi.dll`,
		`\\server\share\amsi.dll`,
	} {
		if _, err := classifyAmsiModulePath(bad); err == nil {
			t.Fatalf("non-canonical amsi.dll path %q was accepted", bad)
		}
	}
}

func TestAmsiPEIdentityRejectsMalformedImage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "amsi.dll")
	if err := os.WriteFile(path, []byte("MZ not-a-pe-image"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := peImageIdentity(path, "AmsiScanBuffer"); err == nil {
		t.Fatal("malformed PE image was accepted")
	}
	if _, _, err := peImageIdentity(filepath.Join(t.TempDir(), "missing.dll"), "AmsiScanBuffer"); err == nil {
		t.Fatal("missing image was accepted")
	}
}

func TestAmsiRecheckMemoIsBoundedAndThrottled(t *testing.T) {
	key := amsiRecheckKey{pid: 424242, creation: 123456789}
	if _, known := amsiRecheckLookup(key); known {
		t.Fatal("unknown identity must not be cached")
	}
	amsiRecheckStore(key, false)
	if patched, known := amsiRecheckLookup(key); !known || patched {
		t.Fatalf("clean verdict must be cached/throttled, got known=%v patched=%v", known, patched)
	}
	amsiRecheckStore(key, true)
	if patched, known := amsiRecheckLookup(key); !known || !patched {
		t.Fatalf("patched verdict must be cached permanently, got known=%v patched=%v", known, patched)
	}
	for index := 0; index < maxAmsiRecheckEntries+32; index++ {
		amsiRecheckStore(amsiRecheckKey{pid: uint32(1000 + index), creation: int64(index)}, false)
	}
	amsiRecheckMu.Lock()
	size := len(amsiRecheckResult)
	amsiRecheckMu.Unlock()
	if size > maxAmsiRecheckEntries {
		t.Fatalf("recheck memo unbounded: %d entries", size)
	}
}
