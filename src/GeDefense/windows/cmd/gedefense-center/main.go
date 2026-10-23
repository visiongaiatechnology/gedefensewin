// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/visiongaiatechnology/gedefense/windows/internal/launcher"
	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func main() {
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()
	if *showVersion {
		_ = winapi.MessageBox("VGT GeDefense Center", fmt.Sprintf("GeDefense Center %s", product.Version), winapi.MBIconInformation)
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
		_ = winapi.MessageBox("VGT GeDefense Center", "GeDefense Center konnte nicht authentifiziert geöffnet werden.", winapi.MBIconError)
	}
}
