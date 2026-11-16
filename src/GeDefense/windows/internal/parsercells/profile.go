// STATUS: DIAMANT VGT SUPREME
//go:build windows

package parsercells

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// The profile document format is a strict, bounded INI dialect:
//
//	# parser-profiles.conf
//	[cell]
//	root = C:\ProgramData\VGT\parser-cells
//	max_active = 4
//
//	[profile:html]
//	max_input_bytes = 4194304
//	max_output_bytes = 1048576
//	max_runtime_ms = 2000
//	max_memory_bytes = 268435456
//	max_processes = 1
//	network_allowed = false
//	required_mitigations = win32k_system_call_disable, font_disable
//
// Rules: full-line comments start with '#' or ';'; unknown sections, unknown
// keys, duplicate keys and duplicate section names are rejected; the document is
// at most MaxDocumentBytes; every missing profile value falls back to the safe
// default; required_mitigations defaults to all mandatory mitigations.
// network_allowed=true is always rejected because cells run without
// capabilities.

// Profile parsing bounds.
const (
	// DefaultMaxActive is the default number of concurrently active cells.
	DefaultMaxActive = 4
	// HardMaxActive is the absolute concurrency ceiling.
	HardMaxActive = 32
	// maxDocumentLines bounds the line count of a profile document.
	maxDocumentLines = 4096
	// maxProfileLineBytes bounds a single line before it is parsed.
	maxProfileLineBytes = 2048
	// maxStagingPathChars bounds the injected staging root.
	maxStagingPathChars = 240
)

// ProfileSet is a fully validated profile document. Profiles are sorted by name
// and bounded by HardMaxProfiles.
type ProfileSet struct {
	// Root is the absolute, canonical staging root injected into the engine.
	Root string
	// MaxActive is the bounded number of concurrently active cells.
	MaxActive int
	// Profiles holds the validated profiles sorted by name.
	Profiles []Profile
}

// Lookup returns the named profile.
func (s ProfileSet) Lookup(name string) (Profile, bool) {
	for _, profile := range s.Profiles {
		if profile.Name == name {
			return profile, true
		}
	}
	return Profile{}, false
}

// ParseProfiles parses and validates a parser-profiles.conf document. The input
// is bounded before any line is inspected; no allocation is proportional to
// attacker-controlled sizes beyond the fixed 64 KiB document ceiling.
func ParseProfiles(data []byte) (ProfileSet, error) {
	if len(data) == 0 {
		return ProfileSet{}, &Error{Op: "profiles.parse", Kind: ErrInvalidProfile, Detail: "empty document"}
	}
	if len(data) > MaxDocumentBytes {
		return ProfileSet{}, &Error{Op: "profiles.parse", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("document %d bytes exceeds %d", len(data), MaxDocumentBytes)}
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxDocumentLines {
		return ProfileSet{}, &Error{Op: "profiles.parse", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("document has %d lines, limit %d", len(lines), maxDocumentLines)}
	}

	root := ""
	maxActive := DefaultMaxActive
	cellSeen := false
	profiles := make([]Profile, 0, 8)
	names := make(map[string]struct{}, 8)
	current := ""
	seenKeys := make(map[string]struct{}, 16)

	for index, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		if len(line) > maxProfileLineBytes {
			return ProfileSet{}, lineError(index, "line exceeds %d bytes", maxProfileLineBytes)
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			section, err := parseSectionHeader(index, trimmed)
			if err != nil {
				return ProfileSet{}, err
			}
			switch {
			case section == "cell":
				if cellSeen {
					return ProfileSet{}, lineError(index, "duplicate [cell] section")
				}
				cellSeen = true
				current = "cell"
			case strings.HasPrefix(section, "profile:"):
				name := strings.TrimPrefix(section, "profile:")
				if err := validateProfileName(name); err != nil {
					return ProfileSet{}, &Error{Op: "profiles.parse", Kind: ErrInvalidProfile,
						Detail: fmt.Sprintf("line %d: %v", index+1, err)}
				}
				if _, duplicate := names[name]; duplicate {
					return ProfileSet{}, lineError(index, "duplicate profile %q", name)
				}
				names[name] = struct{}{}
				if len(profiles) >= HardMaxProfiles {
					return ProfileSet{}, lineError(index, "profile count exceeds %d", HardMaxProfiles)
				}
				profiles = append(profiles, DefaultProfile(name))
				current = section
			default:
				return ProfileSet{}, lineError(index, "unknown section %q", sanitizeText(section))
			}
			seenKeys = make(map[string]struct{}, 16)
			continue
		}

		key, value, err := splitKeyValue(trimmed)
		if err != nil {
			return ProfileSet{}, lineError(index, "%v", err)
		}
		if current == "" {
			return ProfileSet{}, lineError(index, "key %q outside a section", sanitizeText(key))
		}
		if _, duplicate := seenKeys[key]; duplicate {
			return ProfileSet{}, lineError(index, "duplicate key %q", sanitizeText(key))
		}
		seenKeys[key] = struct{}{}

		if current == "cell" {
			switch key {
			case "root":
				root = value
			case "max_active":
				parsed, parseErr := parseBoundedInt(value, 1, HardMaxActive)
				if parseErr != nil {
					return ProfileSet{}, lineError(index, "max_active: %v", parseErr)
				}
				maxActive = int(parsed)
			default:
				return ProfileSet{}, lineError(index, "unknown [cell] key %q", sanitizeText(key))
			}
			continue
		}

		profileIndex := len(profiles) - 1
		if err := applyProfileValue(index, &profiles[profileIndex], key, value); err != nil {
			return ProfileSet{}, err
		}
	}

	if !cellSeen {
		return ProfileSet{}, &Error{Op: "profiles.parse", Kind: ErrInvalidProfile, Detail: "missing [cell] section"}
	}
	if root == "" {
		return ProfileSet{}, &Error{Op: "profiles.parse", Kind: ErrInvalidProfile, Detail: "missing [cell] root"}
	}
	if err := ValidateStagingRoot(root); err != nil {
		return ProfileSet{}, &Error{Op: "profiles.parse", Kind: ErrInvalidProfile, Detail: "invalid [cell] root: " + err.Error()}
	}
	if len(profiles) == 0 {
		return ProfileSet{}, &Error{Op: "profiles.parse", Kind: ErrInvalidProfile, Detail: "no [profile:*] sections"}
	}
	for index := range profiles {
		if err := profiles[index].Validate(); err != nil {
			return ProfileSet{}, &Error{Op: "profiles.parse", Kind: ErrInvalidProfile,
				Detail: fmt.Sprintf("profile %q: %v", profiles[index].Name, err)}
		}
	}
	// Deterministic order independent of document order.
	for left := 0; left < len(profiles); left++ {
		for right := left + 1; right < len(profiles); right++ {
			if profiles[right].Name < profiles[left].Name {
				profiles[left], profiles[right] = profiles[right], profiles[left]
			}
		}
	}
	return ProfileSet{Root: root, MaxActive: maxActive, Profiles: profiles}, nil
}

// LoadProfiles reads, bounds and parses a profile document from disk. The path
// must be absolute and free of traversal components; the document itself is
// bounded before it is parsed.
func LoadProfiles(path string) (ProfileSet, error) {
	if err := validateDocumentPath(path); err != nil {
		return ProfileSet{}, &Error{Op: "profiles.load", Kind: ErrInvalidProfile, Detail: err.Error()}
	}
	file, err := os.Open(path)
	if err != nil {
		return ProfileSet{}, fmt.Errorf("parsercells: open profile document: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, MaxDocumentBytes+1))
	if err != nil {
		return ProfileSet{}, fmt.Errorf("parsercells: read profile document: %w", err)
	}
	if int64(len(data)) > MaxDocumentBytes {
		return ProfileSet{}, &Error{Op: "profiles.load", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("document exceeds %d bytes", MaxDocumentBytes)}
	}
	return ParseProfiles(data)
}

// applyProfileValue applies one validated key to a profile. Unknown keys are
// rejected so a typo cannot silently weaken a limit.
func applyProfileValue(line int, profile *Profile, key, value string) error {
	switch key {
	case "max_input_bytes":
		parsed, err := parseBoundedInt(value, 1, HardMaxInputBytes)
		if err != nil {
			return lineError(line, "max_input_bytes: %v", err)
		}
		profile.MaxInputBytes = parsed
	case "max_output_bytes":
		parsed, err := parseBoundedInt(value, 1, HardMaxOutputBytes)
		if err != nil {
			return lineError(line, "max_output_bytes: %v", err)
		}
		profile.MaxOutputBytes = parsed
	case "max_runtime_ms":
		parsed, err := parseBoundedInt(value, HardMinRuntime.Milliseconds(), HardMaxRuntime.Milliseconds())
		if err != nil {
			return lineError(line, "max_runtime_ms: %v", err)
		}
		profile.MaxRuntime = time.Duration(parsed) * time.Millisecond
	case "max_memory_bytes":
		parsed, err := parseBoundedInt(value, HardMinMemoryBytes, HardMaxMemoryBytes)
		if err != nil {
			return lineError(line, "max_memory_bytes: %v", err)
		}
		profile.MaxMemoryBytes = parsed
	case "max_processes":
		parsed, err := parseBoundedInt(value, 1, 1)
		if err != nil {
			return lineError(line, "max_processes: %v", err)
		}
		profile.MaxProcesses = int(parsed)
	case "network_allowed":
		allowed, err := strconv.ParseBool(value)
		if err != nil {
			return lineError(line, "network_allowed: %v", err)
		}
		if allowed {
			return lineError(line, "network_allowed=true is forbidden: cells have zero capabilities")
		}
		profile.NetworkAllowed = false
	case "required_mitigations":
		mitigations, err := parseMitigationList(value)
		if err != nil {
			return lineError(line, "required_mitigations: %v", err)
		}
		profile.RequiredMitigations = mitigations
	default:
		return lineError(line, "unknown profile key %q", sanitizeText(key))
	}
	return nil
}

// parseMitigationList parses a comma separated mitigation list. An empty list is
// invalid: a profile must state what isolation it relies on.
func parseMitigationList(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("empty list")
	}
	parts := strings.Split(value, ",")
	if len(parts) > len(MandatoryMitigations()) {
		return nil, fmt.Errorf("more than %d entries", len(MandatoryMitigations()))
	}
	mitigations := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if !supportedMitigation(name) {
			return nil, fmt.Errorf("unsupported mitigation %q", sanitizeText(name))
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("duplicate mitigation %q", name)
		}
		seen[name] = struct{}{}
		mitigations = append(mitigations, name)
	}
	return mitigations, nil
}

// parseBoundedInt parses a base-10 integer in an inclusive range.
func parseBoundedInt(value string, minimum, maximum int64) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, errors.New("not a base-10 integer")
	}
	if parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("value %d outside [%d,%d]", parsed, minimum, maximum)
	}
	return parsed, nil
}

// parseSectionHeader parses "[name]" with no trailing text.
func parseSectionHeader(line int, trimmed string) (string, error) {
	if !strings.HasSuffix(trimmed, "]") || len(trimmed) < 3 {
		return "", lineError(line, "malformed section header")
	}
	section := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	if section == "" {
		return "", lineError(line, "empty section name")
	}
	if strings.ContainsAny(section, "[] ") {
		return "", lineError(line, "invalid section name %q", sanitizeText(section))
	}
	return section, nil
}

// splitKeyValue splits "key = value" and rejects empty parts.
func splitKeyValue(trimmed string) (string, string, error) {
	separator := strings.IndexByte(trimmed, '=')
	if separator <= 0 {
		return "", "", errors.New("expected key = value")
	}
	key := strings.TrimSpace(trimmed[:separator])
	value := strings.TrimSpace(trimmed[separator+1:])
	if key == "" {
		return "", "", errors.New("empty key")
	}
	if value == "" {
		return "", "", fmt.Errorf("empty value for %q", sanitizeText(key))
	}
	for index := 0; index < len(key); index++ {
		value := key[index]
		isLower := value >= 'a' && value <= 'z'
		isDigit := value >= '0' && value <= '9'
		if !isLower && !isDigit && value != '_' {
			return "", "", fmt.Errorf("invalid key %q", sanitizeText(key))
		}
	}
	return key, value, nil
}

// lineError builds a bounded parse error that names the one-based line number.
func lineError(line int, format string, arguments ...any) error {
	return &Error{Op: "profiles.parse", Kind: ErrInvalidProfile,
		Detail: fmt.Sprintf("line %d: %s", line+1, sanitizeText(fmt.Sprintf(format, arguments...)))}
}

// ValidateStagingRoot validates an injected absolute, canonical staging root and
// rejects traversal, device/UNC namespaces and reparse points. It is exported
// so callers can pre-flight a root without parsing a document.
func ValidateStagingRoot(value string) error {
	if value == "" {
		return errors.New("staging root must not be empty")
	}
	if !utf8.ValidString(value) {
		return errors.New("staging root is not valid UTF-8")
	}
	if strings.ContainsRune(value, 0) {
		return errors.New("staging root contains a NUL byte")
	}
	if len(value) > maxStagingPathChars {
		return fmt.Errorf("staging root longer than %d characters", maxStagingPathChars)
	}
	if strings.HasPrefix(value, `\\`) || strings.HasPrefix(value, `//`) {
		return errors.New("UNC and device namespaces are rejected")
	}
	if !filepath.IsAbs(value) {
		return errors.New("staging root must be absolute")
	}
	volume := filepath.VolumeName(value)
	if len(volume) != 2 || volume[1] != ':' {
		return errors.New("staging root must use a drive-letter volume")
	}
	if filepath.Clean(value) != value {
		return errors.New("staging root must be canonical (no trailing separator, no . or .. components)")
	}
	for _, component := range strings.FieldsFunc(value, func(r rune) bool { return r == '\\' || r == '/' }) {
		if component == "." || component == ".." {
			return errors.New("staging root contains a relative component")
		}
	}
	if value == volume+`\` {
		return errors.New("staging root must not be a volume root")
	}
	name, err := syscall.UTF16PtrFromString(value)
	if err != nil {
		return fmt.Errorf("staging root encoding: %w", err)
	}
	attributes, err := syscall.GetFileAttributes(name)
	if err != nil {
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("staging root attribute query: %w", err)
	}
	if attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("staging root is a reparse point")
	}
	if attributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("staging root exists but is not a directory")
	}
	return nil
}

// validateDocumentPath accepts an absolute document path with no traversal
// components. It does not follow the path; LoadProfiles bounds the content.
func validateDocumentPath(path string) error {
	if path == "" {
		return errors.New("document path must not be empty")
	}
	if strings.ContainsRune(path, 0) {
		return errors.New("document path contains a NUL byte")
	}
	if len(path) > maxStagingPathChars {
		return fmt.Errorf("document path longer than %d characters", maxStagingPathChars)
	}
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return errors.New("UNC and device namespaces are rejected")
	}
	if !filepath.IsAbs(path) {
		return errors.New("document path must be absolute")
	}
	if filepath.Clean(path) != path {
		return errors.New("document path must be canonical")
	}
	for _, component := range strings.FieldsFunc(path, func(r rune) bool { return r == '\\' || r == '/' }) {
		if component == "." || component == ".." {
			return errors.New("document path contains a relative component")
		}
	}
	return nil
}
