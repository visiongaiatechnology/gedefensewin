// STATUS: PLATIN VGT SUPREME
//go:build windows

package trust

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

var (
	defaultOnce     sync.Once
	defaultVerifier *Verifier
)

// Default returns the process-wide verifier for the machine-installed product
// tree. If the Program Files location cannot be resolved the verifier denies
// every path: the self-protection exemption then only covers processes bound by
// PID identity or the tracked-child registry, never by path.
func Default() *Verifier {
	defaultOnce.Do(func() {
		programFiles := strings.TrimSpace(os.Getenv("ProgramW6432"))
		if programFiles == "" {
			programFiles = strings.TrimSpace(os.Getenv("ProgramFiles"))
		}
		anchor, err := product.ResolveInstallAnchor(programFiles)
		if err != nil {
			defaultVerifier = NewVerifier(product.InstallAnchor{}, nil, 0)
			return
		}
		defaultVerifier = NewVerifier(anchor, winapi.ValidateReparseFreeLocalPath, time.Minute)
	})
	return defaultVerifier
}
