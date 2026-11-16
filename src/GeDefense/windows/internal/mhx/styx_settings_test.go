// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"fmt"
	"strings"
	"testing"
)

func enabledStyxSettings() StyxSettings {
	settings := DefaultStyxSettings()
	settings.Enabled = true
	settings.Mode = StyxModeObserve
	return settings
}

func TestDefaultStyxSettings(t *testing.T) {
	settings := DefaultStyxSettings()
	if settings.Enabled || settings.Mode != StyxModeOff {
		t.Fatalf("default settings must be disabled/off, got %+v", settings)
	}
	if settings.Allowlist == nil || settings.DNSResolvers == nil {
		t.Fatal("default settings must carry non-nil empty lists")
	}
	if settings.EffectiveMode() != StyxModeOff || settings.IsEnforcing() {
		t.Fatal("default settings effective mode must be off")
	}
	normalized, err := NormalizeStyxSettings(settings)
	if err != nil {
		t.Fatalf("default settings rejected: %v", err)
	}
	if normalized.Mode != StyxModeOff || normalized.Thresholds != DefaultStyxBeaconThresholds() {
		t.Fatalf("normalized defaults = %+v", normalized)
	}
}

func TestNormalizeStyxSettingsModes(t *testing.T) {
	settings := enabledStyxSettings()
	settings.Mode = " MONITOR "
	normalized, err := NormalizeStyxSettings(settings)
	if err != nil {
		t.Fatalf("monitor alias rejected: %v", err)
	}
	if normalized.Mode != StyxModeObserve {
		t.Fatalf("monitor alias normalized to %q, want %q", normalized.Mode, StyxModeObserve)
	}
	settings.Mode = "Enforce"
	normalized, err = NormalizeStyxSettings(settings)
	if err != nil || normalized.Mode != StyxModeEnforce || !normalized.IsEnforcing() {
		t.Fatalf("enforce mode normalized wrong: %+v, %v", normalized, err)
	}
	if _, err := NormalizeStyxSettings(StyxSettings{Enabled: true, Mode: "block"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	// A disabled namespace may never request an active mode.
	disabled := DefaultStyxSettings()
	disabled.Mode = StyxModeEnforce
	if _, err := NormalizeStyxSettings(disabled); err == nil {
		t.Fatal("disabled settings with mode=enforce accepted")
	}
}

func TestNormalizeStyxSettingsRejectsInertRules(t *testing.T) {
	inert := DefaultStyxSettings()
	inert.Enabled = true
	inert.Allowlist = []string{"10.0.0.0/8"}
	if _, err := NormalizeStyxSettings(inert); err == nil {
		t.Fatal("mode=off with an allowlist was accepted although it has no effect")
	}
	inert = DefaultStyxSettings()
	inert.Enabled = true
	inert.DNSResolvers = []string{"8.8.8.8/32"}
	if _, err := NormalizeStyxSettings(inert); err == nil {
		t.Fatal("mode=off with DNS resolvers was accepted although it has no effect")
	}
}

func TestNormalizeStyxSettingsAllowlist(t *testing.T) {
	settings := enabledStyxSettings()
	settings.Mode = StyxModeEnforce
	settings.Allowlist = []string{"10.1.2.3/8", "10.0.0.0/8", "2001:db8::/32", "2001:db8::/32"}
	normalized, err := NormalizeStyxSettings(settings)
	if err != nil {
		t.Fatalf("valid allowlist rejected: %v", err)
	}
	if len(normalized.Allowlist) != 2 {
		t.Fatalf("allowlist was not canonicalised/deduplicated: %v", normalized.Allowlist)
	}
	if normalized.Allowlist[0] != "10.0.0.0/8" || normalized.Allowlist[1] != "2001:db8::/32" {
		t.Fatalf("allowlist canonical order = %v", normalized.Allowlist)
	}
	prefixes, err := normalized.AllowPrefixes()
	if err != nil || len(prefixes) != 2 {
		t.Fatalf("AllowPrefixes = %v, %v", prefixes, err)
	}
	// IPv4 before IPv6 independently of input order.
	settings.Allowlist = []string{"2001:db8::/32", "10.0.0.0/8"}
	normalized, err = NormalizeStyxSettings(settings)
	if err != nil {
		t.Fatalf("allowlist rejected: %v", err)
	}
	if normalized.Allowlist[0] != "10.0.0.0/8" {
		t.Fatalf("IPv4 prefix not sorted first: %v", normalized.Allowlist)
	}
}

func TestNormalizeStyxSettingsRejectsInvalidAllowEntries(t *testing.T) {
	settings := enabledStyxSettings()
	settings.Mode = StyxModeEnforce
	cases := []string{
		"0.0.0.0/0",
		"::/0",
		"10.0.0.0/3",
		"2001:db8::/7",
		"not-a-cidr",
		"10.0.0.0/33",
		"::ffff:10.0.0.0/108",
		"169.254.169.254/32", // inside the mandatory metadata veto
		"169.254.0.0/16",     // the metadata veto itself
		"224.0.0.0/4",        // multicast veto
	}
	for _, entry := range cases {
		settings.Allowlist = []string{entry}
		if _, err := NormalizeStyxSettings(settings); err == nil {
			t.Fatalf("allowlist entry %q was accepted but must fail closed", entry)
		}
	}
}

func TestNormalizeStyxSettingsCapsAndResolvers(t *testing.T) {
	settings := enabledStyxSettings()
	settings.Mode = StyxModeEnforce
	tooMany := make([]string, StyxMaxAllowlistEntries+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("10.%d.%d.0/24", index/256, index%256)
	}
	settings.Allowlist = tooMany
	if _, err := NormalizeStyxSettings(settings); err == nil {
		t.Fatal("allowlist above the cap was accepted")
	}
	settings.Allowlist = nil
	resolvers := make([]string, StyxMaxDNSResolvers+1)
	for index := range resolvers {
		resolvers[index] = fmt.Sprintf("192.0.2.%d/32", index%256)
	}
	settings.DNSResolvers = resolvers
	if _, err := NormalizeStyxSettings(settings); err == nil {
		t.Fatal("DNS resolver list above the cap was accepted")
	}
	settings.DNSResolvers = []string{"8.8.8.8", "8.8.8.8/32", "2001:4860:4860::8888/128"}
	normalized, err := NormalizeStyxSettings(settings)
	if err != nil {
		t.Fatalf("valid resolver list rejected: %v", err)
	}
	if len(normalized.DNSResolvers) != 2 || normalized.DNSResolvers[0] != "8.8.8.8/32" {
		t.Fatalf("resolver list not canonicalised: %v", normalized.DNSResolvers)
	}
	prefixes, err := normalized.DNSResolverPrefixes()
	if err != nil || len(prefixes) != 2 {
		t.Fatalf("DNSResolverPrefixes = %v, %v", prefixes, err)
	}
	invalid := enabledStyxSettings()
	invalid.Mode = StyxModeEnforce
	invalid.DNSResolvers = []string{"bad/99"}
	if _, err := NormalizeStyxSettings(invalid); err == nil {
		t.Fatal("invalid resolver CIDR accepted")
	}
}

func TestNormalizeStyxSettingsThresholds(t *testing.T) {
	settings := enabledStyxSettings()
	settings.Thresholds = StyxBeaconThresholds{}
	normalized, err := NormalizeStyxSettings(settings)
	if err != nil {
		t.Fatalf("omitted threshold block not defaulted: %v", err)
	}
	if normalized.Thresholds != DefaultStyxBeaconThresholds() {
		t.Fatalf("omitted thresholds = %+v", normalized.Thresholds)
	}
	custom := DefaultStyxBeaconThresholds()
	custom.PeriodicityMinSamples = 20
	custom.PeriodicityMaxCV = 0.2
	custom.ExfilRatio = 12
	custom.MaxIncidentsPerMinute = 3
	custom.DedupeSeconds = 120
	custom.FlowTTLSeconds = 600
	settings.Thresholds = custom
	if _, err := NormalizeStyxSettings(settings); err != nil {
		t.Fatalf("valid custom thresholds rejected: %v", err)
	}
	bad := []StyxBeaconThresholds{
		func() StyxBeaconThresholds {
			value := DefaultStyxBeaconThresholds()
			value.PeriodicityMinSamples = 1
			return value
		}(),
		func() StyxBeaconThresholds {
			value := DefaultStyxBeaconThresholds()
			value.PeriodicityMaxCV = 0
			return value
		}(),
		func() StyxBeaconThresholds {
			value := DefaultStyxBeaconThresholds()
			value.PeriodicityMinIntervalSeconds = 100
			value.PeriodicityMaxIntervalSeconds = 10
			return value
		}(),
		func() StyxBeaconThresholds {
			value := DefaultStyxBeaconThresholds()
			value.ExfilRatio = 0
			return value
		}(),
		func() StyxBeaconThresholds {
			value := DefaultStyxBeaconThresholds()
			value.MaxIncidentsPerMinute = 0
			return value
		}(),
		func() StyxBeaconThresholds {
			value := DefaultStyxBeaconThresholds()
			value.DedupeSeconds = 0
			return value
		}(),
		func() StyxBeaconThresholds {
			value := DefaultStyxBeaconThresholds()
			value.FlowTTLSeconds = -1
			return value
		}(),
	}
	for index, thresholds := range bad {
		settings.Thresholds = thresholds
		if _, err := NormalizeStyxSettings(settings); err == nil {
			t.Fatalf("invalid threshold set %d was accepted: %+v", index, thresholds)
		}
	}
}

func TestStyxSettingsImmutability(t *testing.T) {
	input := enabledStyxSettings()
	input.Mode = StyxModeEnforce
	input.Allowlist = []string{"10.0.0.0/8"}
	input.Thresholds = DefaultStyxBeaconThresholds()
	normalized, err := NormalizeStyxSettings(input)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	clone := normalized.Clone()
	clone.Allowlist[0] = "192.168.0.0/16"
	clone.Thresholds.PeriodicityMinSamples = 1
	if normalized.Allowlist[0] != "10.0.0.0/8" {
		t.Fatal("Clone shares the allowlist slice")
	}
	if normalized.Thresholds.PeriodicityMinSamples == 1 {
		t.Fatal("Clone shares threshold state")
	}
	// Appending to the caller's slice must not extend the normalized copy.
	input.Allowlist = append(input.Allowlist, "192.168.0.0/16")
	if len(normalized.Allowlist) != 1 {
		t.Fatal("normalized settings alias the caller slice")
	}
}

func TestStyxSettingsErrorsAreBounded(t *testing.T) {
	// Error texts carry bounded tokens (max 128 CIDR bytes), never raw secrets.
	settings := enabledStyxSettings()
	settings.Mode = StyxModeEnforce
	settings.Allowlist = []string{strings.Repeat("9", 300)}
	_, err := NormalizeStyxSettings(settings)
	if err == nil {
		t.Fatal("over-long CIDR accepted")
	}
	if len(err.Error()) > 512 {
		t.Fatalf("error text is not bounded: %d bytes", len(err.Error()))
	}
}
