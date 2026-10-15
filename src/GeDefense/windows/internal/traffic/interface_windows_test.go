//go:build windows

package traffic

import (
	"testing"
)

func TestReadInterfacesWindows(t *testing.T) {
	rows, err := ReadInterfaces()
	if err != nil {
		t.Fatalf("ReadInterfaces failed: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected at least one active network interface on Windows host")
	}
	t.Logf("ReadInterfaces returned %d active interfaces", len(rows))
}
