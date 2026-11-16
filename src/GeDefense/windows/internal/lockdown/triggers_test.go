// STATUS: PLATIN VGT SUPREME

package lockdown

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTriggerKindVocabularyAndPriority(t *testing.T) {
	wantPriority := map[TriggerKind]int{
		TriggerManual: 100, TriggerDuressFile: 90, TriggerMHXCritical: 80,
		TriggerWitnessEquivocation: 70, TriggerCanaryAlarm: 60, TriggerTitanBootTrustDrift: 50,
	}
	for kind, priority := range wantPriority {
		if !kind.Valid() {
			t.Fatalf("%s did not validate", kind)
		}
		if kind.Priority() != priority {
			t.Fatalf("%s: unexpected priority %d", kind, kind.Priority())
		}
	}
	if TriggerKind("morpheus").Valid() {
		t.Fatal("an unknown trigger kind validated")
	}
	order := []TriggerKind{
		TriggerManual, TriggerDuressFile, TriggerMHXCritical,
		TriggerWitnessEquivocation, TriggerCanaryAlarm, TriggerTitanBootTrustDrift,
	}
	for index := 1; index < len(order); index++ {
		if order[index-1].Priority() <= order[index].Priority() {
			t.Fatalf("the priority order is not strict at %s", order[index])
		}
	}
}

func TestTriggerValidateMatrix(t *testing.T) {
	valid := Trigger{ID: "mhx-1", Kind: TriggerMHXCritical, Reason: "critical RASP rule"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid trigger was rejected: %v", err)
	}
	cases := map[string]Trigger{
		"empty-id":       {Kind: TriggerManual},
		"long-id":        {ID: strings.Repeat("a", MaxTriggerIDBytes+1), Kind: TriggerManual},
		"id-with-space":  {ID: "trigger id", Kind: TriggerManual},
		"id-control":     {ID: "trigger\x01id", Kind: TriggerManual},
		"unknown-kind":   {ID: "x", Kind: "morpheus"},
		"long-reason":    {ID: "x", Kind: TriggerManual, Reason: strings.Repeat("r", MaxReasonBytes+1)},
		"reason-control": {ID: "x", Kind: TriggerManual, Reason: "line\nbreak"},
		"long-severity":  {ID: "x", Kind: TriggerManual, Severity: strings.Repeat("s", 65)},
	}
	for name, trigger := range cases {
		if err := trigger.Validate(); !errors.Is(err, ErrInvalidTrigger) {
			t.Fatalf("%s: an invalid trigger validated: %v", name, err)
		}
	}
}

func TestEvaluateTriggerAcceptsAndDedupes(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	policy := CorrelationPolicy{Cooldown: 5 * time.Minute, Dedupe: 5 * time.Minute}
	first := Trigger{ID: "mhx-1", Kind: TriggerMHXCritical, Reason: "critical"}
	outcome := EvaluateTrigger(policy, CorrelationState{}, first, now)
	if !outcome.Accepted || outcome.Decision != DecisionAccepted {
		t.Fatalf("the first automatic trigger was not accepted: %+v", outcome)
	}
	if outcome.State.AutomaticKind != TriggerMHXCritical || outcome.State.AutomaticAt.IsZero() {
		t.Fatalf("the correlation state was not updated: %+v", outcome.State)
	}
	// Same identity inside the dedupe window: suppressed and counted.
	duplicate := EvaluateTrigger(policy, outcome.State, first, now.Add(time.Minute))
	if duplicate.Accepted || duplicate.Decision != DecisionDuplicate {
		t.Fatalf("a duplicate trigger was accepted: %+v", duplicate)
	}
	if duplicate.State.Guards != 1 {
		t.Fatalf("the suppressed candidate was not counted: %d", duplicate.State.Guards)
	}
	// After the dedupe window the same identity is accepted again.
	afterDedupe := EvaluateTrigger(policy, outcome.State, first, now.Add(DefaultDedupe+time.Second))
	if !afterDedupe.Accepted {
		t.Fatalf("the trigger was still suppressed after the dedupe window: %+v", afterDedupe)
	}
}

func TestEvaluateTriggerCooldownAndPriorityEscalation(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	policy := CorrelationPolicy{Cooldown: 5 * time.Minute, Dedupe: 5 * time.Minute}
	titan := Trigger{ID: "titan-1", Kind: TriggerTitanBootTrustDrift}
	state := EvaluateTrigger(policy, CorrelationState{}, titan, now)
	if !state.Accepted {
		t.Fatalf("the first trigger was not accepted: %+v", state)
	}
	// A different, same-or-lower priority candidate inside the cooldown is
	// suppressed.
	lower := Trigger{ID: "titan-2", Kind: TriggerTitanBootTrustDrift}
	cooldown := EvaluateTrigger(policy, state.State, lower, now.Add(time.Minute))
	if cooldown.Accepted || cooldown.Decision != DecisionCooldown {
		t.Fatalf("the cooldown was not enforced: %+v", cooldown)
	}
	// A higher-priority source may escalate and shorten the running cooldown.
	escalation := Trigger{ID: "mhx-1", Kind: TriggerMHXCritical}
	escalated := EvaluateTrigger(policy, state.State, escalation, now.Add(2*time.Minute))
	if !escalated.Accepted || escalated.Decision != DecisionEscalated {
		t.Fatalf("a higher-priority trigger did not escalate: %+v", escalated)
	}
	// The escalated kind is now the running automatic source; a lower one is
	// suppressed again.
	suppressed := EvaluateTrigger(policy, escalated.State, Trigger{ID: "canary-1", Kind: TriggerCanaryAlarm}, now.Add(3*time.Minute))
	if suppressed.Accepted || suppressed.Decision != DecisionCooldown {
		t.Fatalf("a downgrade was accepted during the cooldown: %+v", suppressed)
	}
	// After the cooldown any automatic source is accepted.
	after := EvaluateTrigger(policy, escalated.State, Trigger{ID: "canary-1", Kind: TriggerCanaryAlarm}, now.Add(10*time.Minute))
	if !after.Accepted {
		t.Fatalf("the cooldown never expired: %+v", after)
	}
}

func TestEvaluateTriggerOperatorIntentBypassesGuards(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	policy := CorrelationPolicy{Cooldown: 5 * time.Minute, Dedupe: 5 * time.Minute}
	automatic := Trigger{ID: "mhx-1", Kind: TriggerMHXCritical}
	state := EvaluateTrigger(policy, CorrelationState{}, automatic, now)
	manual := Trigger{ID: "manual-1", Kind: TriggerManual, Operator: true}
	outcome := EvaluateTrigger(policy, state.State, manual, now.Add(time.Minute))
	if !outcome.Accepted || outcome.Decision != DecisionAccepted {
		t.Fatalf("explicit operator intent was suppressed: %+v", outcome)
	}
	if !outcome.State.AutomaticAt.Equal(state.State.AutomaticAt) {
		t.Fatal("an operator trigger must not start the automatic cooldown")
	}
	if outcome.State.TriggerID != "manual-1" {
		t.Fatalf("the dedupe identity was not updated: %+v", outcome.State)
	}
	// The duress kind is explicit intent as well.
	duress := Trigger{ID: "duress-1", Kind: TriggerDuressFile}
	duressOutcome := EvaluateTrigger(policy, state.State, duress, now.Add(time.Minute))
	if !duressOutcome.Accepted {
		t.Fatalf("the duress trigger was suppressed: %+v", duressOutcome)
	}
}

func TestEvaluateTriggerInvalidCandidate(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	outcome := EvaluateTrigger(CorrelationPolicy{}, CorrelationState{}, Trigger{}, now)
	if outcome.Accepted || outcome.Decision != DecisionInvalid {
		t.Fatalf("an invalid candidate was accepted: %+v", outcome)
	}
	if outcome.Detail == "" {
		t.Fatal("the invalid decision has no detail")
	}
}

func TestEvaluateTriggerZeroWindowsDisablesGuards(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	policy := CorrelationPolicy{Cooldown: 0, Dedupe: 0}
	first := Trigger{ID: "mhx-1", Kind: TriggerMHXCritical}
	state := EvaluateTrigger(policy, CorrelationState{}, first, now)
	if !state.Accepted {
		t.Fatalf("the first trigger was not accepted: %+v", state)
	}
	second := EvaluateTrigger(policy, state.State, first, now.Add(time.Second))
	if !second.Accepted {
		t.Fatalf("zero windows still suppressed a candidate: %+v", second)
	}
}
