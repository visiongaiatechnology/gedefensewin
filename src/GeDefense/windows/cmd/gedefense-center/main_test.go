// STATUS: DIAMANT VGT SUPREME
//go:build windows

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/userlaunch"
)

// TestCenterDeElevationRefusalMessageIsHonest guards the fail-closed operator
// text: it must state that no elevated browser is started and must never claim
// an elevated fallback (the FIND-WIN-023 defect).
func TestCenterDeElevationRefusalMessageIsHonest(t *testing.T) {
	message := centerDeElevationRefusalMessage(&userlaunch.DeElevationError{Reason: "hand-over to the unprivileged desktop shell failed"})
	for _, want := range []string{
		"ohne Administratorrechte",
		"kein Browser",
		"hand-over to the unprivileged desktop shell failed",
		"Als Administrator ausführen",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("refusal message misses %q:\n%s", want, message)
		}
	}
	if strings.Contains(message, "läuft weiterhin") {
		t.Fatalf("refusal message still describes an elevated fallback:\n%s", message)
	}
}

func TestDeElevationFailureReasonFallsBackToContractText(t *testing.T) {
	if reason := deElevationFailureReason(errors.New("opaque")); !strings.Contains(reason, "unprivilegierten") {
		t.Fatalf("fallback reason is not specific: %q", reason)
	}
	if reason := deElevationFailureReason(&userlaunch.DeElevationError{Reason: "executable path unavailable"}); reason != "executable path unavailable" {
		t.Fatalf("typed reason lost: %q", reason)
	}
}
