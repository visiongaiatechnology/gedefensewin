// STATUS: DIAMANT VGT SUPREME
package main

import (
	"archive/zip"
	"bytes"
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
