// STATUS: DIAMANT VGT SUPREME
package main

import (
	"archive/zip"
	"bytes"
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
