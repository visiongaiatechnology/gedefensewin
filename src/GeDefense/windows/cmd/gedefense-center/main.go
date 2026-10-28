// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/visiongaiatechnology/gedefense/windows/internal/launcher"
	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
	"github.com/visiongaiatechnology/gedefense/windows/internal/userlaunch"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func main() {
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()
	if *showVersion {
		_ = winapi.MessageBox("VGT GeDefense Center", fmt.Sprintf("GeDefense Center %s", product.Version), winapi.MBIconInformation)
		return
	}
	// The Center is designed as an unprivileged UI process. An inherited
	// elevated token (auto-elevated Setup started the tray, "Run as
	// administrator") is handed back to the interactive desktop shell before any
	// single-instance state is claimed; a Chromium window must never inherit the
	// administrator token.
	if relaunchCenterUnelevated() {
		return
	}
	// The single-instance objects are resolved through the hardened helper: a
	// pre-created or unverifiable mutex must not suppress the console for this
	// session (HP-FIND-005 availability rule). Delegation to an existing window
	// only happens when the claim is trusted and a live Center window exists.
	mutexClaim, claimErr := winapi.CreateSingleInstanceMutex("Center.Instance.v5")
	if claimErr != nil {
		winapi.ReportError("center single-instance claim", claimErr)
	} else {
		defer func() { winapi.ReportError("center mutex close", mutexClaim.Close()) }()
	}
	legitWindow := false
	if hwnd, windowErr := winapi.FindGeDefenseWindow(); windowErr == nil && hwnd != 0 {
		legitWindow = true
	}
	primary, tampered := winapi.ResolveSingleInstance(mutexClaim, legitWindow, claimErr)
	if tampered {
		winapi.ReportError("center single-instance integrity", errors.New("pre-created or unverifiable single-instance object"))
	}
	if !primary {
		if hwnd, windowErr := winapi.FindGeDefenseWindow(); windowErr == nil && hwnd != 0 {
			_ = winapi.BringWindowToForeground(hwnd)
		}
		return
	}
	if err := launcher.Open(); err != nil {
		_ = winapi.MessageBox("VGT GeDefense Center", centerLaunchFailureMessage(err), winapi.MBIconError)
	}
}

// relaunchCenterUnelevated hands an elevated Center over to the unprivileged
// desktop shell user. It reports true only when a replacement process was
// started; this process then exits with status 0. A failed hand-over is
// recorded in the launch diagnostic log and the Center keeps working elevated
// as a documented fallback instead of blocking the operator.
func relaunchCenterUnelevated() (relaunched bool) {
	executable, err := os.Executable()
	if err != nil {
		recordCenterDeElevationFailure(fmt.Errorf("executable path unavailable: %w", err))
		return false
	}
	relaunched, err = userlaunch.RelaunchUnelevatedIfNeeded(executable, nil)
	if err != nil {
		recordCenterDeElevationFailure(err)
		return false
	}
	return relaunched
}

func recordCenterDeElevationFailure(err error) {
	if userlaunch.IsElevated() {
		launcher.RecordElevationFallback(err)
	}
}

// centerLaunchFailureMessage builds the specific operator dialog for a failed
// launch: category-specific cause, remediation hint and the diagnostic log path.
func centerLaunchFailureMessage(err error) string {
	summary, hint := launcher.Describe(err)
	var message strings.Builder
	message.WriteString("GeDefense Center konnte nicht geöffnet werden.\n\nUrsache: ")
	message.WriteString(summary)
	if hint != "" {
		message.WriteString("\n\nHinweis: ")
		message.WriteString(hint)
	}
	if path, pathErr := launcher.DiagnosticLogPath(); pathErr == nil {
		message.WriteString("\n\nDetails: ")
		message.WriteString(path)
	}
	return message.String()
}
