// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
)

// installedVersionAt reads the VERSION file of an existing installation. An
// empty result means "no installation found" and must never block a fresh
// install.
func installedVersionAt(programFiles string) string {
	if !filepath.IsAbs(programFiles) {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Clean(programFiles), "VGT", "GeDefense", "VERSION"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

type releaseVersion struct {
	major, minor, patch int
	prerelease          string
}

func parseReleaseVersion(value string) (releaseVersion, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return releaseVersion{}, errors.New("empty version")
	}
	core := value
	pre := ""
	if index := strings.IndexByte(core, '-'); index >= 0 {
		pre = core[index+1:]
		core = core[:index]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return releaseVersion{}, fmt.Errorf("invalid version %q", value)
	}
	numbers := make([]int, 3)
	for i, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 || number > 1_000_000 {
			return releaseVersion{}, fmt.Errorf("invalid version %q", value)
		}
		numbers[i] = number
	}
	return releaseVersion{major: numbers[0], minor: numbers[1], patch: numbers[2], prerelease: pre}, nil
}

// compareReleaseVersions returns +1 when left is newer, -1 when right is newer
// and 0 when equal. A release is newer than its pre-release (5.3.0 > 5.3.0-beta.2).
func compareReleaseVersions(left, right string) (int, error) {
	a, err := parseReleaseVersion(left)
	if err != nil {
		return 0, err
	}
	b, err := parseReleaseVersion(right)
	if err != nil {
		return 0, err
	}
	for _, pair := range [][2]int{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if pair[0] > pair[1] {
			return 1, nil
		}
		if pair[0] < pair[1] {
			return -1, nil
		}
	}
	switch {
	case a.prerelease == "" && b.prerelease != "":
		return 1, nil
	case a.prerelease != "" && b.prerelease == "":
		return -1, nil
	case a.prerelease == b.prerelease:
		return 0, nil
	default:
		return strings.Compare(a.prerelease, b.prerelease), nil
	}
}

// refuseDowngrade reports whether an existing newer installation must block
// this installer (anti-rollback). Equal versions are allowed for repair.
func refuseDowngrade(installed, candidate string) bool {
	if strings.TrimSpace(installed) == "" {
		return false
	}
	comparison, err := compareReleaseVersions(installed, candidate)
	if err != nil {
		// An unparseable installed version must not silently allow a downgrade.
		return true
	}
	return comparison > 0
}

// enforceNoDowngrade is called before any payload extraction. The installer
// must not replace a newer installation with an older signed package.
func enforceNoDowngrade(uninstall bool) error {
	if uninstall {
		return nil
	}
	programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
	installed := installedVersionAt(programFiles)
	if refuseDowngrade(installed, product.Version) {
		return fmt.Errorf("Downgrade abgelehnt: installierte Version %s ist neuer als Installer %s", installed, product.Version)
	}
	return nil
}
