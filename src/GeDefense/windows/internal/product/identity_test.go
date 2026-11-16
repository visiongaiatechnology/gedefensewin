// STATUS: PLATIN VGT SUPREME
package product

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const semanticVersionPattern = `^\d+\.\d+\.\d+(-beta\.[1-9][0-9]*)?$`

// projectRootFromPackage walks up from the package directory to the source tree
// root (the directory that contains VERSION). It returns "" when the test runs
// outside the full source tree (for example inside an extracted binary-only
// payload), in which case the identity gate is skipped rather than guessed.
func projectRootFromPackage(t *testing.T) string {
	t.Helper()
	current, err := os.Getwd()
	if err != nil {
		t.Skipf("working directory unavailable: %v", err)
	}
	for depth := 0; depth < 8; depth++ {
		if _, err := os.Stat(filepath.Join(current, "VERSION")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return ""
}

// TestSourceIdentityIsConsistent enforces the authoritative identity chain
// documented in SOURCE-IDENTITY.md: VERSION == product.Version == newest
// CHANGELOG heading. This closes the SOURCE_IDENTITY_CONFLICT half of
// FIND-WIN-022 with a machine-checked gate instead of prose.
func TestSourceIdentityIsConsistent(t *testing.T) {
	root := projectRootFromPackage(t)
	if root == "" {
		t.Skip("source tree root with VERSION not reachable from package directory")
	}
	rawVersion, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	version := strings.TrimSpace(string(rawVersion))
	if !regexp.MustCompile(semanticVersionPattern).MatchString(version) {
		t.Fatalf("VERSION %q is not a semantic version", version)
	}
	if version != Version {
		t.Fatalf("SOURCE_IDENTITY_CONFLICT: VERSION=%q but product.Version=%q", version, Version)
	}

	changelog, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	heading := regexp.MustCompile(`(?m)^##\s+\[([0-9]+\.[0-9]+\.[0-9]+(?:-beta\.[1-9][0-9]*)?)\]`)
	match := heading.FindSubmatch(changelog)
	if match == nil {
		t.Fatal("CHANGELOG.md has no versioned release heading")
	}
	if got := string(match[1]); got != version {
		t.Fatalf("SOURCE_IDENTITY_CONFLICT: newest CHANGELOG heading is %q but VERSION=%q", got, version)
	}
}
