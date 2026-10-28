// STATUS: DIAMANT VGT SUPREME
//go:build windows

package userlaunch

import (
	"sort"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"
)

func TestShouldRelaunchUnelevated(t *testing.T) {
	tests := []struct {
		name     string
		elevated bool
		marker   string
		expected bool
	}{
		{"standard user", false, "", false},
		{"standard user with marker", false, "1", false},
		{"elevated without marker", true, "", true},
		{"elevated with other marker value", true, "0", true},
		{"elevated with marker guard", true, "1", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := ShouldRelaunchUnelevated(test.elevated, test.marker); actual != test.expected {
				t.Fatalf("ShouldRelaunchUnelevated(%t, %q) = %t, want %t", test.elevated, test.marker, actual, test.expected)
			}
		})
	}
}

func TestCommandLineQuotesAndValidatesTarget(t *testing.T) {
	executable := `C:\Program Files\VGT\GeDefense\bin\GeDefenseCenter.exe`
	line, err := CommandLine(executable, nil)
	if err != nil {
		t.Fatalf("single argument command line rejected: %v", err)
	}
	if line != `"`+executable+`"` {
		t.Fatalf("executable with spaces was not quoted: %q", line)
	}

	tests := []struct {
		name      string
		arguments []string
		expected  string
	}{
		{"plain switch", []string{"--tray"}, ` --tray`},
		{"argument with space", []string{"a b"}, ` "a b"`},
		{"argument with quote", []string{`quote"inside`}, ` quote\"inside`},
		{"empty argument", []string{""}, ` ""`},
		{"several arguments", []string{"--tray", "a b"}, ` --tray "a b"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			line, err := CommandLine(executable, test.arguments)
			if err != nil {
				t.Fatalf("valid arguments rejected: %v", err)
			}
			expected := `"` + executable + `"` + test.expected
			if line != expected {
				t.Fatalf("CommandLine() = %q, want %q", line, expected)
			}
			if strings.Contains(line, "\x00") {
				t.Fatal("command line contains a NUL byte")
			}
		})
	}

	// The escaping is the standard library's Windows contract: the relay must
	// never invent its own quoting rules.
	probe := syscall.EscapeArg("-name=value with space")
	line, err = CommandLine(executable, []string{"-name=value with space"})
	if err != nil {
		t.Fatalf("quoted argument rejected: %v", err)
	}
	if !strings.HasSuffix(line, " "+probe) {
		t.Fatalf("argument was not escaped with syscall.EscapeArg: %q", line)
	}
}

func TestCommandLineRejectsUnsafeTargets(t *testing.T) {
	validExecutable := `C:\Program Files\VGT\GeDefense\bin\GeDefenseCenter.exe`
	tests := []struct {
		name       string
		executable string
		arguments  []string
	}{
		{"empty executable", "", nil},
		{"relative executable", `GeDefenseCenter.exe`, nil},
		{"drive relative executable", `C:GeDefenseCenter.exe`, nil},
		{"wrong extension", `C:\Temp\GeDefenseCenter.bat`, nil},
		{"no extension", `C:\Temp\GeDefenseCenter`, nil},
		{"non canonical path", `C:\Temp\..\GeDefenseCenter.exe`, nil},
		{"forward slash mix", `C:/Program Files/VGT/GeDefenseCenter.exe`, nil},
		{"nul in executable", "C:\\Temp\\GeDefenseCenter.exe\x00", nil},
		{"newline in executable", "C:\\Temp\\GeDefenseCenter.exe\n", nil},
		{"carriage return in executable", "C:\\Temp\\GeDefenseCenter.exe\r", nil},
		{"quote in executable", `C:\Temp\Ge"DefenseCenter.exe`, nil},
		{"reserved character", `C:\Temp\Ge|DefenseCenter.exe`, nil},
		{"trailing space", "C:\\Temp\\GeDefenseCenter.exe ", nil},
		{"trailing dot", `C:\Temp\GeDefenseCenter.exe.`, nil},
		{"too many arguments", validExecutable, []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}},
		{"oversized argument", validExecutable, []string{strings.Repeat("a", maxArgumentBytes+1)}},
		{"nul in argument", validExecutable, []string{"--flag\x00"}},
		{"newline in argument", validExecutable, []string{"--flag\n"}},
		{"carriage return in argument", validExecutable, []string{"--flag\r"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CommandLine(test.executable, test.arguments); err == nil {
				t.Fatalf("unsafe command line accepted: %q %q", test.executable, test.arguments)
			}
		})
	}
}

func TestCommandLineAcceptsBoundarySizes(t *testing.T) {
	executable := `C:\Windows\System32\notepad.exe`
	if _, err := CommandLine(executable, nil); err != nil {
		t.Fatalf("canonical system executable rejected: %v", err)
	}
	arguments := make([]string, maxArguments)
	for index := range arguments {
		arguments[index] = strings.Repeat("a", maxArgumentBytes)
	}
	if _, err := CommandLine(executable, arguments); err != nil {
		t.Fatalf("maximum bounded argument list rejected: %v", err)
	}
}

func TestLaunchAsShellUserRequiresElevation(t *testing.T) {
	if IsElevated() {
		t.Skip("host process is elevated; the non-elevated contract cannot be observed")
	}
	err := LaunchAsShellUser(`C:\Windows\System32\notepad.exe`, nil)
	if err == nil {
		t.Fatal("non-elevated caller was allowed to launch as shell user")
	}
	if !strings.Contains(err.Error(), "not elevated") {
		t.Fatalf("non-elevated error is not specific: %v", err)
	}
}

func TestRelaunchUnelevatedIfNeededIsANoOpWithoutElevation(t *testing.T) {
	if ShouldRelaunchUnelevated(IsElevated(), "") {
		t.Skip("host process is elevated; the relay would really start the Center")
	}
	relaunched, err := RelaunchUnelevatedIfNeeded(`C:\Windows\System32\notepad.exe`, nil)
	if err != nil {
		t.Fatalf("non-elevated relaunch check failed: %v", err)
	}
	if relaunched {
		t.Fatal("non-elevated process reported a relaunch")
	}
}

func TestStartupInfoWMatchesWindowsX64ABI(t *testing.T) {
	// A wrong STARTUPINFOW size makes CreateProcessWithTokenW fail on every
	// elevated de-elevation; the exact x64 size is part of the Win32 contract.
	if size := unsafe.Sizeof(startupInfoW{}); size != 104 {
		t.Fatalf("STARTUPINFOW size = %d, want 104", size)
	}
	if size := unsafe.Sizeof(processInformation{}); size != 24 {
		t.Fatalf("PROCESS_INFORMATION size = %d, want 24", size)
	}
}

func TestUnprivilegedEnvironmentIsSortedMarkedAndDoubleNulTerminated(t *testing.T) {
	t.Setenv(MarkerEnv, "0")
	block, err := unprivilegedEnvironment()
	if err != nil {
		t.Fatalf("environment block rejected: %v", err)
	}
	if len(block) < 2 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatalf("environment block is not double-NUL terminated: tail=%v", block[max(0, len(block)-4):])
	}
	var entries []string
	start := 0
	for index, unit := range block {
		if unit != 0 {
			continue
		}
		if index == start {
			break
		}
		entries = append(entries, string(utf16.Decode(block[start:index])))
		start = index + 1
	}
	if len(entries) == 0 {
		t.Fatal("environment block is empty")
	}
	if !sort.StringsAreSorted(entries) {
		t.Fatalf("environment block is not sorted: %q", entries)
	}
	markerEntries := 0
	for _, entry := range entries {
		if strings.EqualFold(entry, MarkerEnv+"=1") {
			markerEntries++
			continue
		}
		if strings.HasPrefix(strings.ToUpper(entry), MarkerEnv+"=") {
			t.Fatalf("stale marker value survived in the environment block: %q", entry)
		}
	}
	if markerEntries != 1 {
		t.Fatalf("expected exactly one marker entry, got %d", markerEntries)
	}
}
