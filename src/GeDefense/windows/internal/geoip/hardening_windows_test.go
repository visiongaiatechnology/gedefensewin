// STATUS: DIAMANT VGT SUPREME
//go:build windows

package geoip

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeoDatasetOpenRejectsReparsePointFinalComponent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "junction")
	if err := exec.Command("cmd", "/c", "mklink", "/J", link, target).Run(); err != nil {
		t.Skipf("junction creation is unavailable in this environment: %v", err)
	}
	if _, err := openGeoIPRegularFile(link); err == nil {
		t.Fatal("reparse-point dataset path was opened without reparse rejection")
	}
}
