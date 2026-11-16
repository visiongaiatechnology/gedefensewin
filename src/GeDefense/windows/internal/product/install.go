// STATUS: PLATIN VGT SUPREME
package product

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	// InstallRelativePath is the fixed, administrator-owned location of the
	// installed product tree below the machine Program Files directory. It is a
	// policy constant, not a user preference: every self-protection and trust
	// decision must anchor to this tree instead of matching path substrings.
	InstallRelativePath = `VGT\GeDefense`

	// ReleaseThumbprint pins the SHA-1 thumbprint of the VGT release signing
	// certificate (single source of truth: certificates/release-thumbprint.txt).
	// It is used for release-artifact and caller-authenticity checks; it is not a
	// user-configurable value.
	ReleaseThumbprint = "1E7B1641FC2E8EB82735216829C13721E3B9D895"
)

// InstallAnchor is a validated reference to the trusted product tree. It exists
// so security decisions can be expressed as "is this path inside the installed
// product tree?" instead of "does this path contain a marker substring?". The
// former cannot be forged by an unprivileged user, the latter trivially can.
//
// The zero value is invalid and matches nothing (fail-closed).
type InstallAnchor struct {
	root string
}

// NewInstallAnchor validates and normalises an absolute, local install root.
// Relative paths, UNC/device paths, non-drive paths and NUL bytes are rejected
// because none of them can denote the administrator-owned product tree.
func NewInstallAnchor(root string) (InstallAnchor, error) {
	candidate, err := normaliseLocalPath(root)
	if err != nil {
		return InstallAnchor{}, err
	}
	return InstallAnchor{root: candidate}, nil
}

// ResolveInstallAnchor derives the product tree anchor from the machine
// Program Files directory supplied by the caller. Keeping the environment read
// outside this package makes the resolution testable and avoids hidden global
// state.
func ResolveInstallAnchor(programFiles string) (InstallAnchor, error) {
	base, err := NewInstallAnchor(programFiles)
	if err != nil {
		return InstallAnchor{}, fmt.Errorf("product install anchor: %w", err)
	}
	root := filepath.Join(base.root, InstallRelativePath)
	return NewInstallAnchor(root)
}

// Root returns the normalised install root in lower case. It is empty for the
// zero anchor.
func (a InstallAnchor) Root() string {
	return a.root
}

// Valid reports whether the anchor was constructed successfully.
func (a InstallAnchor) Valid() bool {
	return a.root != ""
}

// Contains reports whether path is the install root itself or a descendant of
// it. Containment is component-aware: "C:\Program Files\VGT\GeDefenseEvil"
// does not match. Path traversal is neutralised by cleaning the candidate
// before the comparison, so "…\GeDefense\..\..\Windows" resolves outside the
// anchor and is rejected. Relative, UNC and device paths never match.
func (a InstallAnchor) Contains(path string) bool {
	if !a.Valid() {
		return false
	}
	candidate, err := normaliseLocalPath(path)
	if err != nil {
		return false
	}
	if candidate == a.root {
		return true
	}
	return strings.HasPrefix(candidate, a.root+string(filepath.Separator))
}

// normaliseLocalPath converts a path into the canonical local form used for all
// trust comparisons: absolute drive path, cleaned, lower case. Quotes and
// surrounding whitespace are tolerated because Windows command lines and
// registry values legitimately carry them.
func normaliseLocalPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	trimmed = strings.Trim(trimmed, `"`)
	if trimmed == "" {
		return "", errors.New("product path: empty path")
	}
	if strings.IndexByte(trimmed, 0) >= 0 {
		return "", errors.New("product path: NUL byte rejected")
	}
	if !filepath.IsAbs(trimmed) {
		return "", errors.New("product path: absolute path required")
	}
	clean := filepath.Clean(trimmed)
	volume := filepath.VolumeName(clean)
	if len(volume) != 2 || volume[1] != ':' || !isASCIILetter(volume[0]) {
		return "", errors.New("product path: local drive path required (UNC and device paths rejected)")
	}
	// A drive-relative path such as "C:VGT" has a volume but no root. It is
	// resolved against the current directory of the caller and therefore never
	// a trustworthy identity.
	if !strings.HasPrefix(clean, volume+string(filepath.Separator)) {
		return "", errors.New("product path: drive-absolute path required")
	}
	return strings.ToLower(clean), nil
}

func isASCIILetter(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
}
