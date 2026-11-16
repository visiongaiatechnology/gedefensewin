// STATUS: PLATIN VGT SUPREME

package lockdown

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultSettingsMatchSpec(t *testing.T) {
	settings := DefaultSettings()
	if settings.Enabled || settings.DMEnabled {
		t.Fatal("the shipped lockdown default must be inert and must not activate DM")
	}
	if !settings.ClearRequiresExplicitEpoch {
		t.Fatal("clear_requires_explicit_epoch must default to true")
	}
	if settings.Cooldown != DefaultCooldown || settings.Dedupe != DefaultDedupe {
		t.Fatalf("unexpected default windows: cooldown=%s dedupe=%s", settings.Cooldown, settings.Dedupe)
	}
	if DefaultCooldown != 5*time.Minute || DefaultDedupe != 5*time.Minute {
		t.Fatal("the shipped cooldown/dedupe must be five minutes")
	}
	want := PhaseSelection{
		Network: true, USB: true, Thunderbolt: true, Hardening: false,
		Brokers: true, Parsers: true, Sessions: true, DeviceMapper: false,
	}
	if settings.Phases != want {
		t.Fatalf("unexpected default phase selection: %+v", settings.Phases)
	}
	if settings.Phases.DeviceMapper {
		t.Fatal("the DM phase must be off by default")
	}
	if err := settings.Validate(); err != nil {
		t.Fatalf("the shipped default must validate: %v", err)
	}
	// Clone is a value copy: a mutated clone never changes the original.
	clone := settings.Clone()
	clone.Enabled = true
	clone.Phases.USB = false
	if settings.Enabled || !settings.Phases.USB {
		t.Fatal("clone aliased the original settings")
	}
}

func TestSettingsValidateRejectsOutOfBounds(t *testing.T) {
	cases := map[string]func(*Settings){
		"cooldown-negative":     func(s *Settings) { s.Cooldown = -time.Second },
		"cooldown-over-bound":   func(s *Settings) { s.Cooldown = MaxCooldown + time.Second },
		"dedupe-negative":       func(s *Settings) { s.Dedupe = -time.Second },
		"dedupe-over-bound":     func(s *Settings) { s.Dedupe = MaxDedupe + time.Second },
		"enabled-without-phase": func(s *Settings) { s.Enabled = true; s.Phases = PhaseSelection{} },
		"dm-phase-without-activation": func(s *Settings) {
			s.Phases.DeviceMapper = true
			s.DMEnabled = false
		},
		"dm-activation-without-phase": func(s *Settings) {
			s.Phases.DeviceMapper = false
			s.DMEnabled = true
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			settings := DefaultSettings()
			mutate(&settings)
			if err := settings.Validate(); !errors.Is(err, ErrInvalidSettings) {
				t.Fatalf("out-of-bounds settings were accepted: %v", err)
			}
		})
	}
}

func TestSettingsValidateAcceptsDocumentedValues(t *testing.T) {
	settings := DefaultSettings()
	settings.Enabled = true
	settings.Cooldown = 0
	settings.Dedupe = 0
	if err := settings.Validate(); err != nil {
		t.Fatalf("a documented value was rejected: %v", err)
	}
	settings = DefaultSettings()
	settings.Enabled = true
	settings.Phases.DeviceMapper = true
	settings.DMEnabled = true
	if err := settings.Validate(); err != nil {
		t.Fatalf("the explicit DM two-key arming was rejected: %v", err)
	}
	disabled := Settings{}
	if err := disabled.Validate(); err != nil {
		t.Fatalf("a fully inert zero setting must validate: %v", err)
	}
}

func TestPhaseSelectionOrderIsFixed(t *testing.T) {
	selection := selectionOf(PhaseDeviceMapper, PhaseNetwork, PhaseBrokers, PhaseUSB)
	got := selection.Enabled()
	want := []PhaseName{PhaseNetwork, PhaseUSB, PhaseBrokers, PhaseDeviceMapper}
	if len(got) != len(want) {
		t.Fatalf("unexpected selected phases: %v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("phase order is not fixed: got %v want %v", got, want)
		}
	}
	if !selection.Any() {
		t.Fatal("a non-empty selection must report Any")
	}
	if (PhaseSelection{}).Any() {
		t.Fatal("an empty selection must not report Any")
	}
}

func TestPhaseSequenceReturnsCopy(t *testing.T) {
	sequence := PhaseSequence()
	if len(sequence) != len(phaseSequence) {
		t.Fatalf("unexpected phase sequence length: %d", len(sequence))
	}
	sequence[0] = PhaseDeviceMapper
	again := PhaseSequence()
	if again[0] != PhaseNetwork {
		t.Fatal("PhaseSequence exposed the internal mutable slice")
	}
	for _, name := range again {
		if !phaseNameValid(name) {
			t.Fatalf("unknown phase name in the sequence: %q", name)
		}
	}
	if phaseNameValid("RULES") {
		t.Fatal("an unknown phase name validated")
	}
}

func TestValidateReason(t *testing.T) {
	if err := validateReason("operator clear after review"); err != nil {
		t.Fatalf("a documented reason was rejected: %v", err)
	}
	for name, reason := range map[string]string{
		"empty":    "",
		"too-long": string(make([]byte, MaxReasonBytes+1)),
		"control":  "operator\nclear",
		"nul-byte": "operator\x00clear",
	} {
		if err := validateReason(reason); !errors.Is(err, ErrInvalidReason) {
			t.Fatalf("%s: an invalid reason was accepted: %v", name, err)
		}
	}
}

func TestTruncateTextBoundsAndKeepsUTF8(t *testing.T) {
	if got := truncateText("  a\nb  ", 10); got != "a b" {
		t.Fatalf("unexpected flattening: %q", got)
	}
	if got := truncateText("äöüß", 5); got != "äö" {
		t.Fatalf("the truncation split a UTF-8 sequence: %q", got)
	}
	if got := truncateText("bounded", 3); got != "bou" {
		t.Fatalf("unexpected truncation: %q", got)
	}
}
