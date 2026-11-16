// STATUS: PLATIN VGT SUPREME

package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewSettingsNormalizes(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	rawPin := make([]byte, 32)
	for index := range rawPin {
		rawPin[index] = byte(index)
	}
	base64Pin := base64.StdEncoding.EncodeToString(rawPin)
	settings, err := NewSettings(Settings{
		Enabled: true, Endpoint: "https://witness.example.com", SPKIPin: base64Pin,
		ReceiptPublicKey: provider.Ed25519PublicKey(), HostID: testHostID,
		AgentVersion: testAgent, OutboxPath: filepath.Join(t.TempDir(), "outbox.enc"),
	})
	if err != nil {
		t.Fatalf("NewSettings with a base64 pin: %v", err)
	}
	if wanted := hex.EncodeToString(rawPin); settings.SPKIPin != wanted {
		t.Fatalf("normalized pin is %q, want %q", settings.SPKIPin, wanted)
	}
	if settings.Interval != DefaultInterval || settings.Timeout != DefaultTimeout {
		t.Fatalf("defaults are interval=%s timeout=%s", settings.Interval, settings.Timeout)
	}
	if settings.String() == "" {
		t.Fatal("redacted String is empty")
	}
	summary := settings.String()
	for _, secret := range []string{settings.Endpoint, settings.SPKIPin, settings.OutboxPath,
		hex.EncodeToString(settings.ReceiptPublicKey)} {
		if secret != "" && strings.Contains(summary, secret) {
			t.Fatalf("redacted String leaks %q", secret)
		}
	}
}

func TestSettingsValidateFailClosed(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	valid := func() Settings {
		settings, err := NewSettings(Settings{
			Enabled: true, Endpoint: "https://witness.example.com",
			SPKIPin: strings.Repeat("ab", 32), ReceiptPublicKey: publicKey,
			HostID: testHostID, AgentVersion: testAgent,
			OutboxPath: filepath.Join(t.TempDir(), "outbox.enc"),
		})
		if err != nil {
			t.Fatalf("valid settings rejected: %v", err)
		}
		return settings
	}
	cases := []struct {
		name string
		edit func(*Settings)
	}{
		{"missing host id", func(settings *Settings) { settings.HostID = "" }},
		{"host id control char", func(settings *Settings) { settings.HostID = "host\x00" }},
		{"missing agent version", func(settings *Settings) { settings.AgentVersion = "" }},
		{"agent version whitespace", func(settings *Settings) { settings.AgentVersion = " 5.3.0" }},
		{"missing endpoint", func(settings *Settings) { settings.Endpoint = "" }},
		{"http endpoint", func(settings *Settings) { settings.Endpoint = "http://witness.example.com" }},
		{"non-443 endpoint", func(settings *Settings) { settings.Endpoint = "https://witness.example.com:8443" }},
		{"userinfo endpoint", func(settings *Settings) { settings.Endpoint = "https://user:pass@witness.example.com" }},
		{"query endpoint", func(settings *Settings) { settings.Endpoint = "https://witness.example.com/?token=1" }},
		{"fragment endpoint", func(settings *Settings) { settings.Endpoint = "https://witness.example.com/#x" }},
		{"localhost endpoint", func(settings *Settings) { settings.Endpoint = "https://localhost" }},
		{"metadata endpoint", func(settings *Settings) { settings.Endpoint = "https://169.254.169.254" }},
		{"missing pin", func(settings *Settings) { settings.SPKIPin = "" }},
		{"bad pin", func(settings *Settings) { settings.SPKIPin = "abc" }},
		{"missing receipt key", func(settings *Settings) { settings.ReceiptPublicKey = nil }},
		{"short receipt key", func(settings *Settings) { settings.ReceiptPublicKey = ed25519.PublicKey("short") }},
		{"missing outbox path", func(settings *Settings) { settings.OutboxPath = "" }},
		{"relative outbox path", func(settings *Settings) { settings.OutboxPath = "outbox.enc" }},
		{"non-canonical outbox path", func(settings *Settings) {
			settings.OutboxPath = filepath.Join(t.TempDir(), "a") + string(filepath.Separator) + ".." + string(filepath.Separator) + "b"
		}},
		{"interval too small", func(settings *Settings) { settings.Interval = time.Second }},
		{"interval too large", func(settings *Settings) { settings.Interval = 48 * time.Hour }},
		{"timeout too small", func(settings *Settings) { settings.Timeout = 100 * time.Millisecond }},
		{"timeout too large", func(settings *Settings) { settings.Timeout = 2 * time.Minute }},
		{"policy generation overflow", func(settings *Settings) { settings.PolicyGeneration = maxCounter + 1 }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			settings := valid()
			testCase.edit(&settings)
			if err := settings.Validate(); !errors.Is(err, ErrSettingsInvalid) {
				t.Fatalf("Validate error is %v, want ErrSettingsInvalid", err)
			}
		})
	}
	// Disabled settings may omit the transport anchor but never the host id.
	disabled := Settings{HostID: testHostID, AgentVersion: testAgent}
	if err := disabled.Validate(); err != nil {
		t.Fatalf("minimal disabled settings rejected: %v", err)
	}
	disabled.HostID = ""
	if err := disabled.Validate(); !errors.Is(err, ErrSettingsInvalid) {
		t.Fatalf("disabled settings without host id error is %v", err)
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid settings rejected: %v", err)
	}
}

func TestParseSPKIPin(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef")
	cases := []struct {
		name    string
		pin     string
		wantErr bool
	}{
		{"lowercase hex", hex.EncodeToString(raw), false},
		{"uppercase hex", strings.ToUpper(hex.EncodeToString(raw)), false},
		{"base64", base64.StdEncoding.EncodeToString(raw), false},
		{"base64 raw url", base64.RawURLEncoding.EncodeToString(raw), false},
		{"empty", "", true},
		{"short", "abcd", true},
		{"garbage", "not-a-pin", true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			decoded, err := ParseSPKIPin(testCase.pin)
			if testCase.wantErr {
				if err == nil {
					t.Fatal("ParseSPKIPin accepted an invalid pin")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSPKIPin rejected a valid pin: %v", err)
			}
			if len(decoded) != 32 {
				t.Fatalf("decoded pin has %d bytes", len(decoded))
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	cases := []struct {
		name         string
		endpoint     string
		allowPrivate bool
		wantErr      bool
	}{
		{"public https", "https://witness.example.com", false, false},
		{"explicit port 443", "https://witness.example.com:443", false, false},
		{"http", "http://witness.example.com", false, true},
		{"other port", "https://witness.example.com:8443", false, true},
		{"localhost", "https://localhost", false, true},
		{"localhost subdomain", "https://a.localhost", false, true},
		{"metadata name", "https://metadata.google.internal", false, true},
		{"private ip literal", "https://10.0.0.1", false, true},
		{"private ip allowed", "https://10.0.0.1", true, false},
		{"loopback allowed", "https://127.0.0.1", true, false},
		{"metadata ip always refused", "https://169.254.169.254", true, true},
		{"aliyun metadata refused", "https://100.100.100.200", true, true},
		{"whitespace", " https://witness.example.com", false, true},
		{"empty", "", false, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := validateEndpoint(testCase.endpoint, testCase.allowPrivate)
			if testCase.wantErr && err == nil {
				t.Fatalf("validateEndpoint accepted %q", testCase.endpoint)
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("validateEndpoint rejected %q: %v", testCase.endpoint, err)
			}
		})
	}
}

func TestForbiddenDestinationIP(t *testing.T) {
	cases := []struct {
		address      string
		allowPrivate bool
		forbidden    bool
	}{
		{"8.8.8.8", false, false},
		{"10.1.2.3", false, true},
		{"10.1.2.3", true, false},
		{"172.16.0.1", false, true},
		{"192.168.1.1", false, true},
		{"127.0.0.1", false, true},
		{"127.0.0.1", true, false},
		{"169.254.169.254", false, true},
		{"169.254.169.254", true, true},
		{"100.100.100.200", true, true},
		{"fd00:ec2::254", true, true},
		{"fd00::1", false, true},
		{"2001:4860:4860::8888", false, false},
		{"0.0.0.0", false, true},
	}
	for _, testCase := range cases {
		address := netip.MustParseAddr(testCase.address)
		if got := forbiddenDestinationIP(address, testCase.allowPrivate); got != testCase.forbidden {
			t.Fatalf("forbiddenDestinationIP(%s, %t)=%t, want %t", testCase.address, testCase.allowPrivate, got, testCase.forbidden)
		}
	}
	if !forbiddenDestinationIP(netip.Addr{}, false) {
		t.Fatal("an invalid address must be forbidden")
	}
}
