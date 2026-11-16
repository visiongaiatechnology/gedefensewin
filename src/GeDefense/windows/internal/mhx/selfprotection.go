// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"os"
	"strings"

	"github.com/visiongaiatechnology/gedefense/windows/internal/trust"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

// isGeDefenseSelfOrChild decides whether an observed process belongs to the
// product's own control plane and must therefore not be struck down by
// Paranoia, strict lineage, AMSI, Killerdom or fair scoring.
//
// The decision is evidence-based only:
//   - our own PID or a direct child of our own PID,
//   - a process we spawned and still pin with a kernel handle (the tracked
//     child registry used for hardening, self-healing and telemetry work),
//   - an ancestry chain that contains our PID or a tracked child,
//   - an image inside the administrator-owned installed product tree.
//
// It deliberately does NOT trust a bare image basename, a parent image name, or
// any command-line substring. Those were the CHAIN-WIN-002 bypasses: an
// unprivileged user could create `%TEMP%\vgt\gedefense\payload.exe`, name it
// `gedefense-windows.exe`, or embed the hardened-script path in a command line
// and inherit a complete self-protection exemption.
func isGeDefenseSelfOrChild(event ProcessEvent) bool {
	currentPID := uint32(os.Getpid())
	if currentPID != 0 && (event.PID == currentPID || event.ParentPID == currentPID) {
		return true
	}
	if isTrackedChild(event.PID) || isTrackedChild(event.ParentPID) {
		return true
	}
	for _, ancestor := range event.Ancestry {
		if currentPID != 0 && ancestor.PID == currentPID {
			return true
		}
		if isTrackedChild(ancestor.PID) {
			return true
		}
		if isGeDefenseBinary(ancestor.Path) {
			return true
		}
	}
	return isGeDefenseBinary(event.ImagePath)
}

// isTrackedChild reports whether pid is a child process this service started and
// still pins. PIDs are compared as unsigned values; the registry itself rejects
// pids at or below 4.
func isTrackedChild(pid uint32) bool {
	if pid <= 4 {
		return false
	}
	return winexec.IsTrackedProcess(int(pid))
}

// isGeDefenseBinary authorizes only files that demonstrably live inside the
// installed product tree. The tree is resolved from the machine Program Files
// directory and the candidate must resolve without a reparse-point redirect.
// The check is fail-closed: an unresolved anchor or path verification error
// grants no exemption.
func isGeDefenseBinary(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	return trust.Default().TrustedTreePath(path)
}
