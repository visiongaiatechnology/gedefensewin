// STATUS: PLATIN VGT SUPREME

package witness

// Validated, immutable witness settings. Validation is reject-not-repair: an
// enabled witness without a hardened transport anchor (SPKI pin and Ed25519
// receipt key), without an endpoint or without a host id is refused, never
// silently clamped into an insecure mode. Timing and path bounds are validated
// here once; the runtime only ever sees a normalized copy.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const (
	settingsMaxEndpointBytes   = 512
	settingsMaxHostIDBytes     = 128
	settingsMaxAgentBytes      = 64
	settingsMaxOutboxPathBytes = 512

	// DefaultInterval is the checkpoint cadence used when Interval is zero.
	DefaultInterval = 5 * time.Minute
	// DefaultTimeout bounds one HTTP round trip when Timeout is zero.
	DefaultTimeout = 10 * time.Second

	settingsMinInterval = 30 * time.Second
	settingsMaxInterval = 24 * time.Hour
	settingsMinTimeout  = time.Second
	settingsMaxTimeout  = 60 * time.Second
)

var (
	// ErrSettingsInvalid marks a settings document that must not be activated.
	ErrSettingsInvalid = errors.New("witness settings are invalid")

	// Addresses that are cloud metadata endpoints and are never contacted, even
	// when private destinations are explicitly allowed.
	metadataIPv4    = netip.MustParseAddr("100.100.100.200")
	metadataIPv4AWS = netip.MustParseAddr("169.254.169.254")
	metadataIPv6    = netip.MustParseAddr("fd00:ec2::254")
)

// Settings is the immutable, validated configuration of the witness client. It
// carries no private key material: the Ed25519 signing key and the outbox key
// live behind KeyProvider. NewSettings is the only normalizer; a Settings value
// should be treated as read-only afterwards.
type Settings struct {
	// Enabled activates the engine. While false the package is fully inert: no
	// goroutine, no outbox read/write, no network traffic, no checkpoint.
	Enabled bool
	// Endpoint is the absolute https base URL on port 443 of the external
	// witness. The client appends /v1/checkpoint. It is never logged.
	Endpoint string
	// SPKIPin is the SHA-256 over the server certificate's RawSubjectPublicKeyInfo
	// as 64 lowercase hex characters (hex or base64 on input; normalized to hex).
	SPKIPin string
	// ReceiptPublicKey is the pinned Ed25519 public key that signs witness
	// receipts. It is public, not secret.
	ReceiptPublicKey ed25519.PublicKey
	// HostID identifies this host in checkpoints and binds the outbox AAD.
	HostID string
	// AgentVersion names the producing agent version inside checkpoints.
	AgentVersion string
	// PolicyGeneration is the monotonic policy revision of this host.
	PolicyGeneration uint64
	// Interval is the checkpoint cadence. Zero selects DefaultInterval.
	Interval time.Duration
	// Timeout bounds one HTTP round trip. Zero selects DefaultTimeout.
	Timeout time.Duration
	// OutboxPath is the absolute path of the encrypted outbox file.
	OutboxPath string
	// AllowPrivateDestinations explicitly permits loopback, link-local and
	// private network destinations. It is a configuration decision for
	// self-hosted relays and tests; cloud metadata addresses stay forbidden.
	AllowPrivateDestinations bool
}

// NewSettings normalizes and validates a settings document. The returned value is
// a copy: the caller cannot mutate the internal byte slices afterwards.
func NewSettings(cfg Settings) (Settings, error) {
	out := cfg
	if out.ReceiptPublicKey != nil {
		out.ReceiptPublicKey = append(ed25519.PublicKey(nil), out.ReceiptPublicKey...)
	}
	if out.SPKIPin != "" {
		raw, err := ParseSPKIPin(out.SPKIPin)
		if err != nil {
			return Settings{}, err
		}
		out.SPKIPin = hex.EncodeToString(raw)
	}
	if out.Interval == 0 {
		out.Interval = DefaultInterval
	}
	if out.Timeout == 0 {
		out.Timeout = DefaultTimeout
	}
	if err := out.Validate(); err != nil {
		return Settings{}, err
	}
	return out, nil
}

// Validate checks every documented bound. It never mutates the receiver.
func (s Settings) Validate() error {
	if err := validateHostID(s.HostID); err != nil {
		return err
	}
	if err := validateAgentVersion(s.AgentVersion); err != nil {
		return err
	}
	if s.PolicyGeneration > maxCounter {
		return fmt.Errorf("%w: policy_generation exceeds the JSON-safe bound", ErrSettingsInvalid)
	}
	if s.Interval != 0 && (s.Interval < settingsMinInterval || s.Interval > settingsMaxInterval) {
		return fmt.Errorf("%w: interval must be between %s and %s", ErrSettingsInvalid, settingsMinInterval, settingsMaxInterval)
	}
	if s.Timeout != 0 && (s.Timeout < settingsMinTimeout || s.Timeout > settingsMaxTimeout) {
		return fmt.Errorf("%w: timeout must be between %s and %s", ErrSettingsInvalid, settingsMinTimeout, settingsMaxTimeout)
	}
	if s.OutboxPath != "" {
		if err := validateOutboxPath(s.OutboxPath); err != nil {
			return err
		}
	}
	if s.Endpoint != "" {
		if _, err := validateEndpoint(s.Endpoint, s.AllowPrivateDestinations); err != nil {
			return err
		}
	}
	if s.SPKIPin != "" {
		if _, err := ParseSPKIPin(s.SPKIPin); err != nil {
			return err
		}
	}
	if s.ReceiptPublicKey != nil && len(s.ReceiptPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: receipt public key must be a 32-byte Ed25519 key", ErrSettingsInvalid)
	}
	if s.Enabled {
		if s.Endpoint == "" {
			return fmt.Errorf("%w: an enabled witness requires an endpoint", ErrSettingsInvalid)
		}
		if s.SPKIPin == "" {
			return fmt.Errorf("%w: an enabled witness requires an SPKI pin", ErrSettingsInvalid)
		}
		if s.ReceiptPublicKey == nil {
			return fmt.Errorf("%w: an enabled witness requires a pinned receipt key", ErrSettingsInvalid)
		}
		if s.OutboxPath == "" {
			return fmt.Errorf("%w: an enabled witness requires an absolute outbox path", ErrSettingsInvalid)
		}
	}
	return nil
}

// String returns a redacted summary for logs. It deliberately omits the
// endpoint, the SPKI pin, the receipt key and the outbox path.
func (s Settings) String() string {
	return fmt.Sprintf("witness.Settings{enabled=%t host_id=%q interval=%s timeout=%s}",
		s.Enabled, s.HostID, s.Interval, s.Timeout)
}

// ParseSPKIPin accepts a SHA-256 SPKI pin as hex (64 characters) or as base64 of
// the 32 raw bytes and returns the raw 32 bytes.
func ParseSPKIPin(pin string) ([]byte, error) {
	value := strings.TrimSpace(pin)
	if value == "" {
		return nil, fmt.Errorf("%w: SPKI pin is empty", ErrSettingsInvalid)
	}
	if len(value) == 2*sha256.Size {
		if raw, err := hex.DecodeString(value); err == nil && len(raw) == sha256.Size {
			return raw, nil
		}
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := encoding.DecodeString(value); err == nil && len(raw) == sha256.Size {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("%w: SPKI pin must be a SHA-256 digest as hex or base64", ErrSettingsInvalid)
}

// validateHostID enforces the bounded checkpoint/outbox host identifier charset.
func validateHostID(value string) error {
	if value == "" {
		return fmt.Errorf("%w: host id is required", ErrSettingsInvalid)
	}
	if len(value) > checkpointMaxHostIDBytes {
		return fmt.Errorf("%w: host id exceeds %d bytes", ErrSettingsInvalid, checkpointMaxHostIDBytes)
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		alnum := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if !alnum && char != '.' && char != '-' && char != '_' && char != ':' {
			return fmt.Errorf("%w: host id contains an unsupported character", ErrSettingsInvalid)
		}
	}
	return nil
}

// validateAgentVersion bounds the producing agent version to printable ASCII.
func validateAgentVersion(value string) error {
	if value == "" {
		return fmt.Errorf("%w: agent version is required", ErrSettingsInvalid)
	}
	if len(value) > checkpointMaxAgentVersionBytes {
		return fmt.Errorf("%w: agent version exceeds %d bytes", ErrSettingsInvalid, checkpointMaxAgentVersionBytes)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: agent version must not carry surrounding whitespace", ErrSettingsInvalid)
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return fmt.Errorf("%w: agent version must be printable ASCII", ErrSettingsInvalid)
		}
	}
	return nil
}

// validateOutboxPath requires an absolute, canonical, bounded file path.
func validateOutboxPath(path string) error {
	if len(path) > settingsMaxOutboxPathBytes || strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("%w: outbox path is oversized or contains control characters", ErrSettingsInvalid)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: outbox path must be absolute", ErrSettingsInvalid)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("%w: outbox path must be canonical", ErrSettingsInvalid)
	}
	return nil
}

// validateEndpoint accepts only an absolute https URL on port 443 without
// userinfo, query or fragment. Localhost and cloud metadata hosts are rejected;
// literal private addresses require the explicit AllowPrivateDestinations flag.
func validateEndpoint(endpoint string, allowPrivate bool) (*url.URL, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("%w: endpoint is empty", ErrSettingsInvalid)
	}
	if len(endpoint) > settingsMaxEndpointBytes || strings.ContainsAny(endpoint, "\x00\r\n") {
		return nil, fmt.Errorf("%w: endpoint is oversized or contains control characters", ErrSettingsInvalid)
	}
	if strings.TrimSpace(endpoint) != endpoint {
		return nil, fmt.Errorf("%w: endpoint must not carry surrounding whitespace", ErrSettingsInvalid)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return nil, fmt.Errorf("%w: endpoint must be an absolute URL", ErrSettingsInvalid)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: endpoint must use https", ErrSettingsInvalid)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("%w: endpoint must not contain userinfo", ErrSettingsInvalid)
	}
	if parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, fmt.Errorf("%w: endpoint must not contain a query or fragment", ErrSettingsInvalid)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: endpoint has no host", ErrSettingsInvalid)
	}
	if err := validateEndpointHost(host, allowPrivate); err != nil {
		return nil, err
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return nil, fmt.Errorf("%w: endpoint must use port 443", ErrSettingsInvalid)
	}
	return parsed, nil
}

// validateEndpointHost rejects forbidden names and, when the host is a literal IP,
// addresses that must not be contacted.
func validateEndpointHost(host string, allowPrivate bool) error {
	lower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if lower == "" {
		return fmt.Errorf("%w: endpoint host is empty", ErrSettingsInvalid)
	}
	switch lower {
	case "localhost", "metadata", "instance-data", "metadata.google.internal":
		return fmt.Errorf("%w: endpoint host is forbidden", ErrSettingsInvalid)
	}
	if strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("%w: endpoint host is forbidden", ErrSettingsInvalid)
	}
	if address, err := netip.ParseAddr(lower); err == nil {
		if forbiddenDestinationIP(address, allowPrivate) {
			return fmt.Errorf("%w: endpoint address is forbidden", ErrSettingsInvalid)
		}
	}
	return nil
}

// forbiddenDestinationIP reports whether an address must never be contacted. Cloud
// metadata addresses are always forbidden; loopback, link-local, private and
// unspecified/multicast ranges require an explicit operator decision.
func forbiddenDestinationIP(address netip.Addr, allowPrivate bool) bool {
	if !address.IsValid() {
		return true
	}
	address = address.Unmap()
	if address == metadataIPv4 || address == metadataIPv4AWS || address == metadataIPv6 {
		return true
	}
	switch {
	case address.IsLoopback(), address.IsUnspecified(), address.IsMulticast():
		return !allowPrivate
	case address.IsLinkLocalUnicast(), address.IsLinkLocalMulticast():
		return !allowPrivate
	case address.IsPrivate():
		return !allowPrivate
	}
	return false
}
