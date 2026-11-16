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
	// The Center is an unprivileged UI process. An inherited elevated token
	// (auto-elevated Setup started the tray, "Run as administrator") is handed
	// back to the interactive desktop shell before any single-instance state is
	// claimed; a Chromium window must never inherit the administrator token.
	//
	// The hand-over is fail-closed (FIND-WIN-023): when it cannot be verified,
	// this elevated process reports the cause and exits. It never continues as
	// the elevated UI and never starts a browser with administrator rights.
	relaunched, deElevationErr := relaunchCenterUnelevated()
	if deElevationErr != nil {
		recordCenterDeElevationFailure(deElevationErr)
		_ = winapi.MessageBox("VGT GeDefense Center", centerDeElevationRefusalMessage(deElevationErr), winapi.MBIconError)
		os.Exit(1)
	}
	if relaunched {
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
// started; this process then exits with status 0.
//
// A non-elevated Center is a normal start and returns (false, nil). Any error
// means the elevated process must stop: the caller shows the refusal and exits
// with a non-zero status instead of continuing as an elevated UI.
func relaunchCenterUnelevated() (relaunched bool, err error) {
	if !userlaunch.IsElevated() {
		return false, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return false, &userlaunch.DeElevationError{Reason: "executable path unavailable", Err: err}
	}
	return userlaunch.RelaunchUnelevatedIfNeeded(executable, nil)
}

func recordCenterDeElevationFailure(err error) {
	if userlaunch.IsElevated() {
		launcher.RecordElevationFallback(err)
	}
}

// centerDeElevationRefusalMessage is the honest operator dialog for a refused
// hand-over. It must never suggest that the Center continues with elevated
// rights or that an elevated browser fallback exists.
func centerDeElevationRefusalMessage(err error) string {
	var message strings.Builder
	message.WriteString("GeDefense Center kann nicht ohne Administratorrechte gestartet werden.\n\n")
	message.WriteString("Sicherheitsgrenze: Aus diesem erhöhten Prozess wird kein Browser gestartet. ")
	message.WriteString("Einen Start mit erhöhten Rechten gibt es bewusst nicht.\n\n")
	message.WriteString("Ursache: ")
	message.WriteString(deElevationFailureReason(err))
	message.WriteString("\n\nHinweis: Starten Sie GeDefense Center ohne \"Als Administrator ausführen\" ")
	message.WriteString("über Startmenü oder Taskleiste.")
	if path, pathErr := launcher.DiagnosticLogPath(); pathErr == nil {
		message.WriteString("\n\nDetails: ")
		message.WriteString(path)
	}
	return message.String()
}

func deElevationFailureReason(err error) string {
	var deElevation *userlaunch.DeElevationError
	if errors.As(err, &deElevation) && strings.TrimSpace(deElevation.Reason) != "" {
		return deElevation.Reason
	}
	return "Übergabe an den unprivilegierten Desktop-Benutzer fehlgeschlagen"
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
