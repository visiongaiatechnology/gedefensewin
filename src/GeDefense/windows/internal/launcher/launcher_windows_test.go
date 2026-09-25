// STATUS: DIAMANT VGT SUPREME
//go:build windows

package launcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindChromiumBrowser(t *testing.T) {
	path := findChromiumBrowser()
	if path != "" {
		if !isExecutableFile(path) {
			t.Fatalf("findChromiumBrowser returned non-executable: %q", path)
		}
	}
}

func TestIsExecutableFile(t *testing.T) {
	if isExecutableFile("") {
		t.Fatal("empty path should not be executable")
	}
	dir := t.TempDir()
	if isExecutableFile(dir) {
		t.Fatal("directory should not be recognized as executable file")
	}
	dummyFile := filepath.Join(dir, "test.exe")
	if err := os.WriteFile(dummyFile, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !isExecutableFile(dummyFile) {
		t.Fatal("regular file should be recognized as executable")
	}
}

func TestBootstrapURLRejectsInvalidProgramData(t *testing.T) {
	t.Setenv("ProgramData", "")
	_, err := BootstrapURL()
	if err == nil {
		t.Fatal("expected error when ProgramData is empty")
	}
}
