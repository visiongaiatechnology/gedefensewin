// STATUS: PLATIN VGT SUPREME

package product

import (
	"strings"
	"testing"
)

func TestNewInstallAnchorRejectsUntrustworthyPaths(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"VGT\\GeDefense",
		`.\VGT\GeDefense`,
		`\\server\share\VGT\GeDefense`,
		`\\?\C:\Program Files\VGT\GeDefense`,
		`\\.\C:\Program Files\VGT\GeDefense`,
		"C:VGT",
		"C:",
		"relative",
		"bad\x00path",
	}
	for _, value := range cases {
		if _, err := NewInstallAnchor(value); err == nil {
			t.Fatalf("expected anchor rejection for %q", value)
		}
	}
}

func TestResolveInstallAnchorBuildsAnchoredProductRoot(t *testing.T) {
	anchor, err := ResolveInstallAnchor(`C:\Program Files`)
	if err != nil {
		t.Fatalf("resolve anchor: %v", err)
	}
	if got, want := anchor.Root(), `c:\program files\vgt\gedefense`; got != want {
		t.Fatalf("anchor root = %q, want %q", got, want)
	}
	if !anchor.Valid() {
		t.Fatal("expected valid anchor")
	}
}

func TestInstallAnchorContainmentIsComponentAnchored(t *testing.T) {
	anchor, err := ResolveInstallAnchor(`C:\Program Files`)
	if err != nil {
		t.Fatalf("resolve anchor: %v", err)
	}
	trusted := []string{
		`C:\Program Files\VGT\GeDefense`,
		`C:\Program Files\VGT\GeDefense\`,
		`C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe`,
		`C:\PROGRAM FILES\VGT\GEDEFENSE\bin\GeDefenseCenter.exe`,
		`"C:\Program Files\VGT\GeDefense\bin\GeDefenseTray.exe"`,
		`  C:\Program Files\VGT\GeDefense\engine\Invoke-VgtHardening.ps1  `,
	}
	for _, value := range trusted {
		if !anchor.Contains(value) {
			t.Fatalf("expected trusted containment for %q", value)
		}
	}

	untrusted := []string{
		"",
		`C:\Program Files\VGT\GeDefenseEvil\x.exe`,
		`C:\Program Files\VGT\GeDefense\..\..\evil.exe`,
		`C:\Program Files (x86)\VGT\GeDefense\bin\x.exe`,
		`C:\Users\Public\vgt\gedefense\gedefense-windows.exe`,
		`C:\Users\Public\AppData\Local\Temp\vgt\gedefense\x.exe`,
		`C:\vgt\gedefense\x.exe`,
		`C:\Program Files\VGT\GeDefenseX`,
		`D:\Program Files\VGT\GeDefense\bin\x.exe`,
		`\\server\share\VGT\GeDefense\x.exe`,
		`C:VGT\GeDefense\x.exe`,
		`relative\VGT\GeDefense\x.exe`,
	}
	for _, value := range untrusted {
		if anchor.Contains(value) {
			t.Fatalf("expected containment rejection for %q", value)
		}
	}
}

func TestZeroInstallAnchorMatchesNothing(t *testing.T) {
	var anchor InstallAnchor
	if anchor.Valid() {
		t.Fatal("zero anchor must be invalid")
	}
	if anchor.Contains(`C:\Program Files\VGT\GeDefense\bin\x.exe`) {
		t.Fatal("zero anchor must not match any path")
	}
}

func TestReleaseThumbprintIsPinnedHex(t *testing.T) {
	if len(ReleaseThumbprint) != 40 {
		t.Fatalf("release thumbprint length = %d, want 40", len(ReleaseThumbprint))
	}
	if ReleaseThumbprint != strings.ToUpper(ReleaseThumbprint) {
		t.Fatal("release thumbprint must be upper-case hex")
	}
}
