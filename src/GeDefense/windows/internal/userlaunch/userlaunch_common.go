// STATUS: DIAMANT VGT SUPREME
package userlaunch

// MarkerEnv is set in the environment block of a UI process that was
// deliberately handed over to the unprivileged desktop shell user. It breaks a
// relaunch loop if an elevated process ever inherits the marker.
const MarkerEnv = "VGT_UI_LAUNCHED_UNELEVATED"

// ShouldRelaunchUnelevated reports whether an elevated UI process must hand
// itself over to the unprivileged shell user. It is intentionally pure so the
// decision stays unit-testable without touching the desktop.
func ShouldRelaunchUnelevated(elevated bool, marker string) bool {
	return elevated && marker != "1"
}
