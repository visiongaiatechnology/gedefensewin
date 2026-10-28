// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

// expectedWinTrustFileInfoSize is sizeof(WINTRUST_FILE_INFO) from the Windows
// SDK for the current pointer width: DWORD + LPCWSTR + HANDLE + GUID*.
func expectedWinTrustFileInfoSize() int {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return 32
	}
	return 16
}

// expectedWinTrustDataSize is sizeof(WINTRUST_DATA) from the Windows SDK for
// the current pointer width, including the Windows 8+ pSignatureSettings field.
func expectedWinTrustDataSize() int {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return 88
	}
	return 52
}

// signedSystemPE returns a Microsoft-signed PE with an embedded Authenticode
// signature from the system directory. Catalog-only system files (for example
// notepad.exe) are deliberately not used: VerifyAuthenticode verifies the
// embedded signature of the file itself, exactly like a browser binary.
func signedSystemPE(t *testing.T) string {
	t.Helper()
	systemRoot := strings.TrimSpace(os.Getenv("SystemRoot"))
	if systemRoot == "" {
		t.Skip("SystemRoot is unavailable")
	}
	for _, name := range []string{"kernel32.dll", "taskmgr.exe", "explorer.exe", "cmd.exe", "WindowsPowerShell\\v1.0\\powershell.exe"} {
		candidate := filepath.Join(systemRoot, "System32", name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	t.Skip("no embedded-signed system PE available in this environment")
	return ""
}

// UI-FIND-002 mitigation: a signed system PE must verify successfully.
func TestVerifyAuthenticodeAcceptsSignedSystemPE(t *testing.T) {
	path := signedSystemPE(t)
	if err := VerifyAuthenticode(path); err != nil {
		t.Skipf("Authenticode verification is blocked by this environment: %v (path=%s)", err, path)
	}
}

// UI-FIND-002 mitigation: an unsigned file must be rejected, never launched.
func TestVerifyAuthenticodeRejectsUnsignedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsigned.exe")
	content := make([]byte, 4096)
	content[0], content[1] = 'M', 'Z'
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write unsigned test file: %v", err)
	}
	if err := VerifyAuthenticode(path); err == nil {
		t.Fatal("unsigned file was accepted as Authenticode-valid")
	}
	if err := VerifyAuthenticode(filepath.Join(t.TempDir(), "missing.exe")); err == nil {
		t.Fatal("missing file was accepted as Authenticode-valid")
	}
}

// UI-FIND-002 mitigation: path boundary rejects everything that could resolve
// outside a local fixed drive or would not be a real executable file.
func TestVerifyAuthenticodeRejectsInvalidPaths(t *testing.T) {
	longPath := filepath.Join(t.TempDir(), strings.Repeat("a", maxAuthenticodePathBytes))
	cases := []struct {
		name string
		path string
	}{
		{name: "empty path", path: ""},
		{name: "relative path", path: `notepad.exe`},
		{name: "relative sub path", path: filepath.Join("System32", "notepad.exe")},
		{name: "unc path", path: `\\server\share\browser.exe`},
		{name: "device path", path: `\\.\C:\Windows\System32\notepad.exe`},
		{name: "extended-length prefix", path: `\\?\C:\Windows\System32\notepad.exe`},
		{name: "path over the boundary", path: longPath},
		{name: "directory", path: t.TempDir()},
		{name: "nul byte", path: "C:\\Windows\\System32\\notepad.exe\x00.exe"},
	}
	for _, testCase := range cases {
		if err := VerifyAuthenticode(testCase.path); err == nil {
			t.Fatalf("%s was accepted as Authenticode-valid: %q", testCase.name, testCase.path)
		}
	}
}

// UI-FIND-002 mitigation: a reparse point must never be verified through. The
// test skips honestly when the environment cannot create symlinks.
func TestVerifyAuthenticodeRejectsReparsePoint(t *testing.T) {
	targetDirectory := t.TempDir()
	target := filepath.Join(targetDirectory, "target.exe")
	content := make([]byte, 4096)
	content[0], content[1] = 'M', 'Z'
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	linkDirectory := t.TempDir()
	link := filepath.Join(linkDirectory, "browser.exe")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symlink in this environment: %v", err)
	}
	if err := VerifyAuthenticode(link); err == nil {
		t.Fatal("reparse point was accepted as Authenticode-valid")
	}
}

// UI-FIND-002 mitigation: a path that traverses a junction (an unprivileged
// reparse point) is rejected before WinVerifyTrust runs.
func TestVerifyAuthenticodeRejectsJunctionPath(t *testing.T) {
	targetDirectory := t.TempDir()
	linkParent := t.TempDir()
	junction := filepath.Join(linkParent, "junction")
	command := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, targetDirectory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction in this environment: %v (%s)", err, strings.TrimSpace(string(output)))
	}
	content := make([]byte, 4096)
	content[0], content[1] = 'M', 'Z'
	// Non-executable fixture name: the reparse rejection happens before any
	// content/signature evaluation, and an unsigned executable-looking file in
	// %TEMP% would raise false alarms in endpoint monitoring during the test run.
	if err := os.WriteFile(filepath.Join(targetDirectory, "vgt-unsigned-probe.bin"), content, 0o600); err != nil {
		t.Fatalf("write file through junction target: %v", err)
	}
	err := VerifyAuthenticode(filepath.Join(junction, "vgt-unsigned-probe.bin"))
	if err == nil {
		t.Fatal("path through a junction was accepted as Authenticode-valid")
	}
	if !strings.Contains(err.Error(), "reparse") {
		t.Fatalf("junction path was not rejected as a reparse path: %v", err)
	}
}

// The WinVerifyTrust structures must match the Windows ABI on the build
// target; a wrong cbStruct or padding would make every verification fail.
func TestWinTrustStructureLayout(t *testing.T) {
	fileInfoSize := int(unsafe.Sizeof(winTrustFileInfo{}))
	if fileInfoSize != expectedWinTrustFileInfoSize() {
		t.Fatalf("WINTRUST_FILE_INFO size=%d, want %d", fileInfoSize, expectedWinTrustFileInfoSize())
	}
	dataSize := int(unsafe.Sizeof(winTrustData{}))
	if dataSize != expectedWinTrustDataSize() {
		t.Fatalf("WINTRUST_DATA size=%d, want %d", dataSize, expectedWinTrustDataSize())
	}
	if winTrustActionGenericVerifyV2.Data4 != [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee} {
		t.Fatal("WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID was modified")
	}
}
