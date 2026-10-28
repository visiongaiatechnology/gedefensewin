// STATUS: DIAMANT VGT SUPREME
package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveTraversalIsRejected(t *testing.T) {
	var raw bytes.Buffer
	writer := zip.NewWriter(&raw)
	entry, err := writer.Create("..\\escaped.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("blocked")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractArchive(raw.Bytes(), t.TempDir()); err == nil {
		t.Fatal("archive traversal was accepted")
	}
}

func TestArchiveWindowsPathHazardsAreRejected(t *testing.T) {
	for _, name := range []string{
		`payload/bin/app.exe:stream`,
		`payload/CON.txt`,
		`payload/NUL`,
		`payload/bin/trailing.`,
		`payload/bin/trailing `,
		`C:relative.exe`,
		`payload\\..\\escaped.txt`,
	} {
		t.Run(name, func(t *testing.T) {
			var raw bytes.Buffer
			writer := zip.NewWriter(&raw)
			entry, err := writer.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write([]byte("blocked")); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := extractArchive(raw.Bytes(), t.TempDir()); err == nil {
				t.Fatalf("dangerous archive path %q was accepted", name)
			}
		})
	}
}

func TestArchiveSafePayloadPathIsAccepted(t *testing.T) {
	path, err := safeArchiveRelativePath(`payload/bin/GeDefenseCenter.exe`)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join("payload", "bin", "GeDefenseCenter.exe") {
		t.Fatalf("unexpected normalized path: %q", path)
	}
}

func TestCompareReleaseVersions(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"5.3.0", "5.2.9", 1},
		{"5.3.0", "5.3.0", 0},
		{"5.3.0", "5.3.1", -1},
		{"5.3.0", "5.3.0-beta.2", 1},
		{"5.3.0-beta.2", "5.3.0", -1},
		{"5.10.0", "5.9.9", 1},
	}
	for _, tc := range cases {
		got, err := compareReleaseVersions(tc.left, tc.right)
		if err != nil {
			t.Fatalf("compare %s/%s: %v", tc.left, tc.right, err)
		}
		if got != tc.want {
			t.Fatalf("compare %s/%s = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}
	if _, err := compareReleaseVersions("not-a-version", "5.3.0"); err == nil {
		t.Fatal("invalid version must be rejected")
	}
}

func TestNoDowngradePolicy(t *testing.T) {
	if !refuseDowngrade("5.3.0", "5.2.0") {
		t.Fatal("newer installed version must refuse downgrade")
	}
	if refuseDowngrade("5.3.0", "5.3.0") {
		t.Fatal("equal version must be allowed for repair")
	}
	if refuseDowngrade("5.2.0", "5.3.0") {
		t.Fatal("upgrade must be allowed")
	}
	if !refuseDowngrade("garbage", "5.3.0") {
		t.Fatal("unparseable installed version must fail closed")
	}
	if refuseDowngrade("", "5.3.0") {
		t.Fatal("fresh install must not be blocked")
	}
}

func TestInstalledVersionAt(t *testing.T) {
	root := t.TempDir()
	installDir := filepath.Join(root, "VGT", "GeDefense")
	if err := os.MkdirAll(installDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := installedVersionAt(root); got != "" {
		t.Fatalf("expected no installed version, got %q", got)
	}
	if err := os.WriteFile(filepath.Join(installDir, "VERSION"), []byte("5.3.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := installedVersionAt(root); got != "5.3.0" {
		t.Fatalf("installed version = %q", got)
	}
}
