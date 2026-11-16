// STATUS: PLATIN VGT SUPREME
//go:build !windows

package trust

import "github.com/visiongaiatechnology/gedefense/windows/internal/product"

// Default denies every path on platforms without a Windows install anchor. The
// product ships for Windows; this variant keeps the package buildable for
// cross-platform static analysis without weakening the Windows decision.
func Default() *Verifier {
	return NewVerifier(product.InstallAnchor{}, nil, 0)
}
