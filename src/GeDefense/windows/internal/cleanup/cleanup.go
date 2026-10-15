// STATUS: PLATIN
// Package cleanup preserves deferred resource errors in the operation result.
package cleanup

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// CloseInto requires the address of the caller's named error result.
func CloseInto(result *error, resource io.Closer) {
	if err := resource.Close(); err != nil {
		*result = errors.Join(*result, fmt.Errorf("close resource: %w", err))
	}
}

// RemoveInto permits a temporary file already consumed by an atomic rename.
func RemoveInto(result *error, path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		*result = errors.Join(*result, fmt.Errorf("remove temporary file: %w", err))
	}
}

// RemoveTreeInto is for caller-owned, validated temporary staging directories.
func RemoveTreeInto(result *error, path string) {
	if err := os.RemoveAll(path); err != nil {
		*result = errors.Join(*result, fmt.Errorf("remove staging directory: %w", err))
	}
}
