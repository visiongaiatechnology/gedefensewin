// STATUS: PLATIN VGT SUPREME

package titan

import (
	"testing"
	"time"
)

// TestKillerdomTargetRequiresObservedAttribution proves FIND-WIN-002: a
// four-second temporal correlation can never produce kinetic authority.
func TestKillerdomTargetRequiresObservedAttribution(t *testing.T) {
	observed := Observation{
		Actor: Actor{
			PID:                4242,
			Path:               `C:\Users\Public\payload.exe`,
			CreationUTC:        time.Unix(1700000000, 0).UTC(),
			CorrelationQuality: CorrelationTemporal,
			CorrelationNote:    "temporal only",
		},
		Object:        Object{Name: "Run\\Updater"},
		Authorization: Authorization{Status: TrustCompromised, Reason: "unauthorized persistence"},
	}
	if _, ok := killerdomTargetFor(observed); ok {
		t.Fatal("temporal attribution must not yield a kinetic target")
	}

	observed.Actor.CorrelationQuality = CorrelationNone
	if _, ok := killerdomTargetFor(observed); ok {
		t.Fatal("absent attribution must not yield a kinetic target")
	}

	observed.Actor.CorrelationQuality = CorrelationObserved
	observed.Actor.CreationUTC = time.Time{}
	if _, ok := killerdomTargetFor(observed); ok {
		t.Fatal("observed attribution without creation time must not yield a target")
	}

	observed.Actor.CreationUTC = time.Unix(1700000000, 0).UTC()
	observed.Actor.Path = ""
	if _, ok := killerdomTargetFor(observed); ok {
		t.Fatal("observed attribution without image path must not yield a target")
	}
}

// TestKillerdomTargetCarriesIdentity proves the bridge receives complete identity
// evidence for the responder to re-verify.
func TestKillerdomTargetCarriesIdentity(t *testing.T) {
	created := time.Unix(1700000123, 456000000).UTC()
	observation := Observation{
		Actor: Actor{
			PID:                777,
			Path:               `C:\Users\Public\payload.exe`,
			CreationUTC:        created,
			CorrelationQuality: CorrelationObserved,
		},
		Object:        Object{Name: "Service\\EvilSvc"},
		Authorization: Authorization{Status: TrustCompromised, Reason: "unsigned driver service"},
	}
	target, ok := killerdomTargetFor(observation)
	if !ok {
		t.Fatal("expected kinetic target for observed attribution")
	}
	if target.PID != 777 {
		t.Fatalf("pid = %d, want 777", target.PID)
	}
	if target.CreationUnixNano != created.UnixNano() {
		t.Fatalf("creation = %d, want %d", target.CreationUnixNano, created.UnixNano())
	}
	if target.ImagePath != `C:\Users\Public\payload.exe` {
		t.Fatalf("image path = %q", target.ImagePath)
	}
	if target.Reason == "" {
		t.Fatal("reason must not be empty")
	}
}
