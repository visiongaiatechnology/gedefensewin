// STATUS: PLATIN
package cleanup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type failingCloser struct{ err error }

func (c failingCloser) Close() error { return c.err }

func TestDeferredClosePreservesPrimaryAndCleanupFailure(t *testing.T) {
	primary, secondary := errors.New("operation failed"), errors.New("close failed")
	run := func() (err error) { defer CloseInto(&err, failingCloser{secondary}); return primary }
	err := run()
	if !errors.Is(err, primary) || !errors.Is(err, secondary) {
		t.Fatalf("lost error: %v", err)
	}
}
func TestTemporaryCleanupAcceptsAtomicRenameButNotOtherFailures(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "temporary")
	var result error
	RemoveInto(&result, file)
	if result != nil {
		t.Fatal(result)
	}
	if err := os.Mkdir(file, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(file, "owned"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	RemoveInto(&result, file)
	if result == nil {
		t.Fatal("nonempty directory removal failure was lost")
	}
}
