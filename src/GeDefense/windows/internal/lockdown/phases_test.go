// STATUS: PLATIN VGT SUPREME

package lockdown

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRunEngageAppliesMandatoryReadback(t *testing.T) {
	clock := newFakeClock()
	phase := appliedPhase(PhaseUSB)
	result := runEngage(context.Background(), phase, clock)
	if result.Status != PhaseApplied || !result.Verified {
		t.Fatalf("an acknowledged phase was not applied and verified: %+v", result)
	}
	if result.Action != ActionEngage || result.Phase != PhaseUSB {
		t.Fatalf("unexpected result markers: %+v", result)
	}
	if _, _, verifies := phase.counts(); verifies != 1 {
		t.Fatalf("the read-back was not executed: %d", verifies)
	}
}

func TestRunEngageDowngradesFailedReadback(t *testing.T) {
	clock := newFakeClock()
	phase := appliedPhase(PhaseUSB)
	phase.setVerify(func(context.Context) error { return errors.New("device is still enabled") })
	result := runEngage(context.Background(), phase, clock)
	if result.Status != PhaseFailed || result.Verified {
		t.Fatalf("a failed read-back was reported as applied: %+v", result)
	}
	if !strings.Contains(result.Detail, "read-back verification failed") {
		t.Fatalf("the read-back failure is not named: %q", result.Detail)
	}
}

func TestRunEngageKeepsHonestUnverifiedStatus(t *testing.T) {
	clock := newFakeClock()
	phase := appliedPhase(PhaseBrokers)
	phase.setVerify(func(context.Context) error {
		return fmt.Errorf("%w: no read-back", ErrVerificationUnavailable)
	})
	result := runEngage(context.Background(), phase, clock)
	if result.Status != PhaseApplied || result.Verified {
		t.Fatalf("an unverifiable phase must stay applied but unverified: %+v", result)
	}
	if !strings.Contains(result.Detail, "read-back not available") {
		t.Fatalf("the missing read-back is not named: %q", result.Detail)
	}
}

func TestRunEngageIsolatesPhasePanic(t *testing.T) {
	clock := newFakeClock()
	phase := appliedPhase(PhaseUSB)
	phase.setEngage(func(context.Context) PhaseResult { panic("phase bug") })
	result := runEngage(context.Background(), phase, clock)
	if result.Status != PhaseFailed {
		t.Fatalf("a panicking phase was not reported as failed: %+v", result)
	}
	if !strings.Contains(result.Detail, "panicked") {
		t.Fatalf("the panic is not named: %q", result.Detail)
	}
}

func TestRunReleaseIsolatesPhasePanic(t *testing.T) {
	clock := newFakeClock()
	phase := appliedPhase(PhaseUSB)
	phase.setRelease(func(context.Context) PhaseResult { panic("release bug") })
	result := runRelease(context.Background(), phase, clock)
	if result.Status != PhaseFailed || result.Action != ActionRelease {
		t.Fatalf("a panicking release was not reported as failed: %+v", result)
	}
}

func TestRunEngageHonoursContextDeadline(t *testing.T) {
	clock := newFakeClock()
	phase := &scriptedPhase{
		name: PhaseUSB, timeout: 20 * time.Millisecond,
		engageFn: func(ctx context.Context) PhaseResult {
			<-ctx.Done()
			return PhaseResult{Phase: PhaseUSB, Status: PhaseFailed, Detail: "deadline reached"}
		},
	}
	started := time.Now()
	result := runEngage(context.Background(), phase, clock)
	elapsed := time.Since(started)
	if result.Status != PhaseFailed {
		t.Fatalf("a timed-out phase was reported as applied: %+v", result)
	}
	if elapsed < 15*time.Millisecond {
		t.Fatalf("the phase timeout was not applied: %s", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the phase timeout was not bounded: %s", elapsed)
	}
}

func TestAggregateMatrix(t *testing.T) {
	result := func(name PhaseName, status PhaseStatus) PhaseResult {
		return PhaseResult{Action: ActionEngage, Phase: name, Status: status}
	}
	cases := []struct {
		name    string
		results []PhaseResult
		want    PhaseStatus
	}{
		{"empty", nil, PhaseFailed},
		{"all-applied", []PhaseResult{result(PhaseUSB, PhaseApplied), result(PhaseBrokers, PhaseApplied)}, PhaseApplied},
		{"partial-and-applied", []PhaseResult{result(PhaseUSB, PhaseApplied), result(PhaseBrokers, PhasePartial)}, PhasePartial},
		{"failed-and-applied", []PhaseResult{result(PhaseUSB, PhaseApplied), result(PhaseBrokers, PhaseFailed)}, PhasePartial},
		{"all-failed", []PhaseResult{result(PhaseUSB, PhaseFailed), result(PhaseBrokers, PhaseFailed)}, PhaseFailed},
		{"all-unsupported", []PhaseResult{result(PhaseUSB, PhaseUnsupported), result(PhaseBrokers, PhaseUnsupported)}, PhaseFailed},
		{"all-unavailable", []PhaseResult{result(PhaseUSB, PhaseUnavailable)}, PhaseFailed},
		{"applied-with-unavailable", []PhaseResult{result(PhaseUSB, PhaseApplied), result(PhaseNetwork, PhaseUnavailable)}, PhasePartial},
		// An unsupported phase is a platform fact (for example the Linux-only
		// PARSERS phase on Windows); it does not downgrade a real isolation.
		{"applied-with-unsupported", []PhaseResult{result(PhaseUSB, PhaseApplied), result(PhaseParsers, PhaseUnsupported)}, PhaseApplied},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, summary := Aggregate(test.results)
			if got != test.want {
				t.Fatalf("unexpected aggregate status: got %s want %s (%s)", got, test.want, summary)
			}
			if summary == "" {
				t.Fatal("the aggregate summary is empty")
			}
		})
	}
	if _, summary := Aggregate(nil); len(summary) > MaxDetailBytes*4 {
		t.Fatalf("the aggregate summary is unbounded: %d bytes", len(summary))
	}
}

func TestUnsupportedPhaseIsHonest(t *testing.T) {
	phase := NewUnsupportedPhase(PhaseThunderbolt, "no supported Windows API")
	if phase.Name() != PhaseThunderbolt || phase.Timeout() <= 0 {
		t.Fatalf("unexpected unsupported phase identity: %+v", phase)
	}
	engage := phase.Engage(context.Background())
	if engage.Status != PhaseUnsupported || !strings.Contains(engage.Detail, "NOT_IMPLEMENTED") {
		t.Fatalf("an unsupported phase did not report NOT_IMPLEMENTED: %+v", engage)
	}
	release := phase.Release(context.Background())
	if release.Status != PhaseApplied {
		t.Fatalf("an unsupported phase must have nothing to release: %+v", release)
	}
	if err := phase.Verify(context.Background()); !errors.Is(err, ErrPhaseUnsupported) {
		t.Fatalf("an unsupported phase verified successfully: %v", err)
	}
}

func TestNormalizePhaseResultDowngradesUnknownOutcome(t *testing.T) {
	result := normalizePhaseResult(
		PhaseResult{Phase: "wrong", Status: "locked", Detail: strings.Repeat("x", MaxDetailBytes*3)},
		PhaseUSB, ActionEngage,
	)
	if result.Status != PhaseFailed || result.Phase != PhaseUSB || result.Action != ActionEngage {
		t.Fatalf("an invalid outcome was not downgraded: %+v", result)
	}
	if len(result.Detail) > MaxDetailBytes {
		t.Fatalf("the detail was not bounded: %d", len(result.Detail))
	}
	if !strings.Contains(result.Detail, "invalid outcome") {
		t.Fatalf("the downgrade is not named: %q", result.Detail)
	}
}

func TestValidatePhaseResultRejectsOutOfBounds(t *testing.T) {
	valid := PhaseResult{Action: ActionEngage, Phase: PhaseUSB, Status: PhaseApplied}
	if err := validatePhaseResult(valid); err != nil {
		t.Fatalf("a valid result was rejected: %v", err)
	}
	cases := map[string]PhaseResult{
		"unknown-phase":  {Action: ActionEngage, Phase: "RULES", Status: PhaseApplied},
		"unknown-status": {Action: ActionEngage, Phase: PhaseUSB, Status: "locked"},
		"unknown-action": {Action: "arm", Phase: PhaseUSB, Status: PhaseApplied},
		"huge-targets":   {Action: ActionEngage, Phase: PhaseUSB, Status: PhaseApplied, Targets: MaxPhaseTargets + 1},
		"huge-detail":    {Action: ActionEngage, Phase: PhaseUSB, Status: PhaseApplied, Detail: strings.Repeat("x", MaxDetailBytes*2+1)},
		"huge-duration":  {Action: ActionEngage, Phase: PhaseUSB, Status: PhaseApplied, Duration: 2*MaxPhaseTimeout + time.Second},
	}
	for name, result := range cases {
		if err := validatePhaseResult(result); !errors.Is(err, ErrInvalidPhase) {
			t.Fatalf("%s: an invalid phase result validated: %v", name, err)
		}
	}
}

func TestPhaseSummaryIsBounded(t *testing.T) {
	results := make([]PhaseResult, 0, len(phaseSequence))
	for index, name := range phaseSequence {
		status := PhaseApplied
		if index%2 == 0 {
			status = PhaseUnsupported
		}
		results = append(results, PhaseResult{Action: ActionEngage, Phase: name, Status: status, Detail: strings.Repeat("d", 200)})
	}
	summary := phaseSummary(results)
	if summary == "" {
		t.Fatal("the phase summary is empty")
	}
	if len(summary) > MaxDetailBytes*4 {
		t.Fatalf("the phase summary is unbounded: %d bytes", len(summary))
	}
}
