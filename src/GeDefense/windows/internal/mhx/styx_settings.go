// STATUS: PLATIN VGT SUPREME
package mhx

// Windows V6 Phase 1: the validated, immutable StyX settings namespace.
//
// This is the 1:1 port of the Linux V6 settings/validation contract
// (control/styx_settings.go + styx_policy_plan.go, docs/POINT3-EGRESS-BEACON.md
// §8.3, §13.15): values are validated once, rejected instead of silently
// repaired, and stored canonically. The default is enabled=false, mode=off, so
// an upgrade never changes egress behaviour.
//
// The metadata/DNS veto is deliberately NOT a setting: it is hard-wired in
// styx_policy.go and can never be disabled by an operator revision.

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	// StyxModeOff/Observe/Enforce are the administrable modes. "observe" is the
	// Windows name of the Linux V6 "monitor" mode (telemetry only, no drop);
	// StyxModeMonitor is kept as the Linux-compatible alias.
	StyxModeOff     = "off"
	StyxModeObserve = "observe"
	StyxModeMonitor = StyxModeObserve
	StyxModeEnforce = "enforce"

	// StyxMaxAllowlistEntries / StyxMaxDNSResolvers are the documented list
	// ceilings; a list above the cap is rejected, never truncated.
	StyxMaxAllowlistEntries = 1024
	StyxMaxDNSResolvers     = 256
)

// StyxBeaconThresholds are the tunable detection thresholds. The defaults are
// the exact Linux V6 constants (§8.2); validation rejects values that would
// make a signal meaningless. PeriodicityMinTxBytes defaults to 1 because the
// Windows source only counts an interval when it observed real activity in the
// window; an operator may raise it.
type StyxBeaconThresholds struct {
	PeriodicityMinSamples         int     `json:"periodicityMinSamples"`
	PeriodicityMaxCV              float64 `json:"periodicityMaxCv"`
	PeriodicityMinIntervalSeconds float64 `json:"periodicityMinIntervalSeconds"`
	PeriodicityMaxIntervalSeconds float64 `json:"periodicityMaxIntervalSeconds"`
	PeriodicityMinTxBytes         uint64  `json:"periodicityMinTxBytes"`
	ExfilMinTxBytes               uint64  `json:"exfilMinTxBytes"`
	ExfilRatio                    float64 `json:"exfilRatio"`
	ExfilZeroRxMinSamples         int     `json:"exfilZeroRxMinSamples"`
	ExfilZeroRxMinTxBytes         uint64  `json:"exfilZeroRxMinTxBytes"`
	CanaryVolumeMinTxBytes        uint64  `json:"canaryVolumeMinTxBytes"`
	DirectIPMinTxBytes            uint64  `json:"directIpMinTxBytes"`
	MaxIncidentsPerMinute         int     `json:"maxIncidentsPerMinute"`
	DedupeSeconds                 int     `json:"dedupeSeconds"`
	FlowTTLSeconds                int     `json:"flowTtlSeconds"`
}

// DefaultStyxBeaconThresholds returns the Linux V6 Phase-1 defaults.
func DefaultStyxBeaconThresholds() StyxBeaconThresholds {
	return StyxBeaconThresholds{
		PeriodicityMinSamples:         12,
		PeriodicityMaxCV:              0.30,
		PeriodicityMinIntervalSeconds: 10,
		PeriodicityMaxIntervalSeconds: 3600,
		PeriodicityMinTxBytes:         1,
		ExfilMinTxBytes:               524288,
		ExfilRatio:                    8,
		ExfilZeroRxMinSamples:         8,
		ExfilZeroRxMinTxBytes:         1 << 20,
		CanaryVolumeMinTxBytes:        1 << 20,
		DirectIPMinTxBytes:            65536,
		MaxIncidentsPerMinute:         MaxIncidentsPerMinute,
		DedupeSeconds:                 DedupeSeconds,
		FlowTTLSeconds:                FlowTTLSeconds,
	}
}

// StyxSettings is the operator-facing, validated StyX namespace. Values are
// canonical after NormalizeStyxSettings; callers receive copies, so a Settings
// value behaves as an immutable snapshot.
type StyxSettings struct {
	Enabled      bool                 `json:"enabled"`
	Mode         string               `json:"mode"`
	Allowlist    []string             `json:"allowlist"`
	DNSResolvers []string             `json:"dnsResolvers"`
	Thresholds   StyxBeaconThresholds `json:"thresholds"`
}

// DefaultStyxSettings returns the fail-safe upgrade default: disabled, off, no
// rules, Linux V6 thresholds.
func DefaultStyxSettings() StyxSettings {
	return StyxSettings{
		Enabled:      false,
		Mode:         StyxModeOff,
		Allowlist:    []string{},
		DNSResolvers: []string{},
		Thresholds:   DefaultStyxBeaconThresholds(),
	}
}

// Clone returns a deep copy; no slice is shared with the receiver.
func (s StyxSettings) Clone() StyxSettings {
	out := s
	out.Allowlist = append([]string{}, s.Allowlist...)
	out.DNSResolvers = append([]string{}, s.DNSResolvers...)
	return out
}

// EffectiveMode is the mode that actually applies: a disabled namespace is
// always off, exactly like the Linux V6 effective settings projection.
func (s StyxSettings) EffectiveMode() string {
	if !s.Enabled {
		return StyxModeOff
	}
	switch s.Mode {
	case StyxModeObserve, StyxModeEnforce:
		return s.Mode
	default:
		return StyxModeOff
	}
}

// IsEnforcing reports whether the effective mode may drop traffic.
func (s StyxSettings) IsEnforcing() bool {
	return s.EffectiveMode() == StyxModeEnforce
}

// AllowPrefixes parses the allowlist into canonical prefixes. It returns an
// error instead of guessing if a stored entry is invalid.
func (s StyxSettings) AllowPrefixes() ([]netip.Prefix, error) {
	return styxParsePrefixList("allowlist", s.Allowlist)
}

// DNSResolverPrefixes parses the configured resolver prefixes.
func (s StyxSettings) DNSResolverPrefixes() ([]netip.Prefix, error) {
	return styxParsePrefixList("DNS resolver", s.DNSResolvers)
}

func styxParsePrefixList(kind string, texts []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(texts))
	for _, text := range texts {
		prefix, err := StyxCanonicalPrefix(text)
		if err != nil {
			return nil, fmt.Errorf("styX %s entry %q: %w", kind, text, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// NormalizeStyxSettings validates one settings revision and returns the
// canonical, immutable copy. It fails closed: invalid CIDRs, allow-all rules,
// inert mode=off policies and meaningless thresholds are errors, not repairs.
func NormalizeStyxSettings(in StyxSettings) (StyxSettings, error) {
	mode, err := styxNormalizeMode(in.Mode)
	if err != nil {
		return StyxSettings{}, err
	}
	if !in.Enabled && mode != StyxModeOff {
		return StyxSettings{}, fmt.Errorf("styX mode=%s requires enabled=true; a disabled namespace is always off", mode)
	}
	if mode == StyxModeOff && (len(in.Allowlist) > 0 || len(in.DNSResolvers) > 0) {
		// §13.15: accepting rules while the pipeline is inert would persist a
		// policy the operator believes is enforced. Refuse it visibly.
		return StyxSettings{}, errors.New("styX mode=off with allowlist or DNS resolver rules has no effect; set mode=observe or mode=enforce")
	}
	thresholds, err := styxNormalizeThresholds(in.Thresholds)
	if err != nil {
		return StyxSettings{}, err
	}
	allowlist, err := styxNormalizeAllowlist(in.Allowlist)
	if err != nil {
		return StyxSettings{}, err
	}
	resolvers, err := styxNormalizeResolvers(in.DNSResolvers)
	if err != nil {
		return StyxSettings{}, err
	}
	return StyxSettings{
		Enabled:      in.Enabled,
		Mode:         mode,
		Allowlist:    allowlist,
		DNSResolvers: resolvers,
		Thresholds:   thresholds,
	}, nil
}

// styxNormalizeMode maps the documented aliases onto the canonical mode names.
func styxNormalizeMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", StyxModeOff:
		return StyxModeOff, nil
	case StyxModeObserve:
		return StyxModeObserve, nil
	case "monitor": // documented Linux V6 name, normalised to observe
		return StyxModeObserve, nil
	case StyxModeEnforce:
		return StyxModeEnforce, nil
	default:
		return "", fmt.Errorf("styX mode %q must be off, observe (monitor) or enforce", mode)
	}
}

// styxNormalizeAllowlist canonicalises, deduplicates and sorts the allowlist and
// rejects rules the mandatory metadata veto would silently override.
func styxNormalizeAllowlist(entries []string) ([]string, error) {
	if len(entries) > StyxMaxAllowlistEntries {
		return nil, fmt.Errorf("styX allowlist exceeds %d entries", StyxMaxAllowlistEntries)
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		prefix, err := StyxCanonicalAllowPrefix(entry)
		if err != nil {
			return nil, err
		}
		for _, veto := range styxMetadataVetoPrefixes {
			if styxPrefixesOverlap(prefix, veto) {
				return nil, fmt.Errorf("styX allowlist entry %s overlaps the mandatory veto %s and could never take effect", prefix, veto)
			}
		}
		canonical := prefix.String()
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr().Is4() != prefixes[j].Addr().Is4() {
			return prefixes[i].Addr().Is4()
		}
		return prefixes[i].String() < prefixes[j].String()
	})
	normalized := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		normalized = append(normalized, prefix.String())
	}
	return normalized, nil
}

// styxNormalizeResolvers canonicalises, deduplicates and sorts the resolver
// prefixes used by the DNS pin rule.
func styxNormalizeResolvers(entries []string) ([]string, error) {
	if len(entries) > StyxMaxDNSResolvers {
		return nil, fmt.Errorf("styX DNS resolver list exceeds %d entries", StyxMaxDNSResolvers)
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		prefix, err := StyxCanonicalPrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("styX DNS resolver entry %q: %w", entry, err)
		}
		canonical := prefix.String()
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr().Is4() != prefixes[j].Addr().Is4() {
			return prefixes[i].Addr().Is4()
		}
		return prefixes[i].String() < prefixes[j].String()
	})
	normalized := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		normalized = append(normalized, prefix.String())
	}
	return normalized, nil
}

// styxNormalizeThresholds validates every threshold. A completely omitted
// threshold block inherits the defaults; a partially specified block is
// validated strictly and never silently repaired field by field.
func styxNormalizeThresholds(in StyxBeaconThresholds) (StyxBeaconThresholds, error) {
	if in == (StyxBeaconThresholds{}) {
		return DefaultStyxBeaconThresholds(), nil
	}
	if in.PeriodicityMinSamples < 2 || in.PeriodicityMinSamples > 10000 {
		return StyxBeaconThresholds{}, fmt.Errorf("styX periodicityMinSamples %d must be within 2..10000", in.PeriodicityMinSamples)
	}
	if in.PeriodicityMaxCV <= 0 || in.PeriodicityMaxCV > 100 {
		return StyxBeaconThresholds{}, fmt.Errorf("styX periodicityMaxCv %v must be within (0..100]", in.PeriodicityMaxCV)
	}
	if in.PeriodicityMinIntervalSeconds <= 0 || in.PeriodicityMaxIntervalSeconds <= in.PeriodicityMinIntervalSeconds || in.PeriodicityMaxIntervalSeconds > 86400 {
		return StyxBeaconThresholds{}, fmt.Errorf("styX periodicity interval window [%v..%v] seconds is invalid", in.PeriodicityMinIntervalSeconds, in.PeriodicityMaxIntervalSeconds)
	}
	if in.ExfilRatio < 1 || in.ExfilRatio > 1e9 {
		return StyxBeaconThresholds{}, fmt.Errorf("styX exfilRatio %v must be within [1..1e9]", in.ExfilRatio)
	}
	if in.ExfilZeroRxMinSamples < 2 || in.ExfilZeroRxMinSamples > 10000 {
		return StyxBeaconThresholds{}, fmt.Errorf("styX exfilZeroRxMinSamples %d must be within 2..10000", in.ExfilZeroRxMinSamples)
	}
	if in.MaxIncidentsPerMinute < 1 || in.MaxIncidentsPerMinute > 600 {
		return StyxBeaconThresholds{}, fmt.Errorf("styX maxIncidentsPerMinute %d must be within 1..600", in.MaxIncidentsPerMinute)
	}
	if in.DedupeSeconds < 1 || in.DedupeSeconds > 86400 {
		return StyxBeaconThresholds{}, fmt.Errorf("styX dedupeSeconds %d must be within 1..86400", in.DedupeSeconds)
	}
	if in.FlowTTLSeconds < 1 || in.FlowTTLSeconds > 604800 {
		return StyxBeaconThresholds{}, fmt.Errorf("styX flowTtlSeconds %d must be within 1..604800", in.FlowTTLSeconds)
	}
	return in, nil
}
