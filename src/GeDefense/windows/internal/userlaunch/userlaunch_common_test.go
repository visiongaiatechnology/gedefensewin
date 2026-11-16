// STATUS: DIAMANT VGT SUPREME
package userlaunch

import (
	"errors"
	"strings"
	"testing"
)

func TestDecideStartPolicyIsFailClosed(t *testing.T) {
	tests := []struct {
		name     string
		elevated bool
		marker   string
		expected StartPolicy
	}{
		{"standard user", false, "", StartPolicyProceed},
		{"standard user with marker", false, "1", StartPolicyProceed},
		{"elevated without marker", true, "", StartPolicyRelaunch},
		{"elevated with other marker value", true, "0", StartPolicyRelaunch},
		{"elevated with hand-over marker", true, "1", StartPolicyRefuse},
		{"elevated with unexpected marker value", true, "yes", StartPolicyRelaunch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := DecideStartPolicy(test.elevated, test.marker); actual != test.expected {
				t.Fatalf("DecideStartPolicy(%t, %q) = %v, want %v", test.elevated, test.marker, actual, test.expected)
			}
		})
	}
}

// TestRelaunchUnelevatedNeverLaunchesWhenPolicyRefuses is the regression test
// for the fail-open FIND-WIN-023 defect: an elevated process that may not hand
// over must report a typed error and must not start any relay (and therefore
// never an elevated Chromium).
func TestRelaunchUnelevatedNeverLaunchesWhenPolicyRefuses(t *testing.T) {
	launches := 0
	relaunched, err := relaunchUnelevated(true, "1", `C:\Windows\System32\notepad.exe`, nil, func(string, []string) error {
		launches++
		return nil
	})
	if relaunched {
		t.Fatal("refused de-elevation reported a successful relaunch")
	}
	if launches != 0 {
		t.Fatalf("refused de-elevation still started the launch relay %d time(s)", launches)
	}
	var deElevation *DeElevationError
	if !errors.As(err, &deElevation) {
		t.Fatalf("refusal error is not a *DeElevationError: %v", err)
	}
	if !errors.Is(err, ErrDeElevationUnavailable) {
		t.Fatalf("refusal error does not classify as ErrDeElevationUnavailable: %v", err)
	}
}

func TestRelaunchUnelevatedReportsTypedFailureAndDoesNotFallBack(t *testing.T) {
	launches := 0
	cause := errors.New("shell token unavailable")
	relaunched, err := relaunchUnelevated(true, "", `C:\Windows\System32\notepad.exe`, nil, func(string, []string) error {
		launches++
		return cause
	})
	if relaunched {
		t.Fatal("failed de-elevation reported a successful relaunch")
	}
	if launches != 1 {
		t.Fatalf("launch relay calls = %d, want exactly 1 (no silent retry/fallback)", launches)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("underlying launch failure was lost: %v", err)
	}
	var deElevation *DeElevationError
	if !errors.As(err, &deElevation) {
		t.Fatalf("failure is not a *DeElevationError: %v", err)
	}
	if !strings.Contains(err.Error(), "unprivileged") {
		t.Fatalf("failure does not name the de-elevation contract: %v", err)
	}
}

func TestRelaunchUnelevatedSucceedsOnlyAfterVerifiableHandOver(t *testing.T) {
	launches := 0
	relaunched, err := relaunchUnelevated(true, "", `C:\Windows\System32\notepad.exe`, nil, func(executable string, args []string) error {
		launches++
		if executable == "" || len(args) != 0 {
			t.Fatalf("relay received unexpected target %q %q", executable, args)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("valid hand-over failed: %v", err)
	}
	if !relaunched || launches != 1 {
		t.Fatalf("relaunched=%t launches=%d, want true/1", relaunched, launches)
	}
}

func TestRelaunchUnelevatedIsANoOpForStandardUsers(t *testing.T) {
	launches := 0
	relaunched, err := relaunchUnelevated(false, "", `C:\Windows\System32\notepad.exe`, nil, func(string, []string) error {
		launches++
		return nil
	})
	if err != nil {
		t.Fatalf("standard user decision failed: %v", err)
	}
	if relaunched || launches != 0 {
		t.Fatalf("standard user triggered a relaunch (relaunched=%t launches=%d)", relaunched, launches)
	}
}

func TestDeElevationErrorUnwrapExposesCauseAndSentinel(t *testing.T) {
	cause := errors.New("CreateProcessWithTokenW failed")
	err := &DeElevationError{Reason: "hand-over failed", Err: cause}
	if !errors.Is(err, ErrDeElevationUnavailable) {
		t.Fatalf("sentinel is not reachable: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("cause is not reachable: %v", err)
	}
	if !strings.Contains(err.Error(), "hand-over failed") || !strings.Contains(err.Error(), cause.Error()) {
		t.Fatalf("error text lost reason or cause: %q", err.Error())
	}
}
