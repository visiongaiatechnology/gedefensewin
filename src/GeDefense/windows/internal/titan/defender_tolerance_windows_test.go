// STATUS: PLATIN VGT SUPREME
//go:build windows

package titan

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func findSignedDefenderPlatformImage(t *testing.T) string {
	t.Helper()
	resetTitanSignatureProbes()
	pattern := filepath.Join(titanProgramDataDir(), "Microsoft", "Windows Defender", "Platform", "*", "MsMpEng.exe")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("Defender platform glob: %v", err)
	}
	for _, match := range matches {
		if titanFileSignatureStatus(match) == signatureStatusValid {
			return match
		}
	}
	return ""
}

// FIND-WIN-010 positive integration check against the real Windows trust store:
// a Microsoft-signed Defender binary in the canonical platform directory is
// tolerated.
func TestRealSignedDefenderPlatformBinaryIsTolerated(t *testing.T) {
	image := findSignedDefenderPlatformImage(t)
	if image == "" {
		t.Skip("no validly signed Microsoft Defender platform binary available on this host")
	}
	policy := Policy{SchemaVersion: PolicySchemaVersion, Mode: ModeBalanced, Reason: "FIND-WIN-010 real-signature check"}
	observation := Observation{
		Type:   EventPersistenceChanged,
		Object: Object{Kind: ObjectService, Name: "WinDefend", Path: `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend`, Change: "IMAGE_PATH"},
		Actor:  Actor{Image: "MsMpEng.exe", Path: image},
	}
	auth := Evaluate(policy, nil, observation, time.Now().UTC(), 0)
	if auth.Status != TrustTolerated {
		t.Fatalf("real signed Defender platform binary was not tolerated: %+v", auth)
	}
}

// FIND-WIN-010 negative integration check: canonical Defender path with an
// unsigned body is rejected by the real Authenticode verifier.
func TestRealUnsignedBinaryInCanonicalDefenderPathIsRejected(t *testing.T) {
	fakeProgramData := filepath.Join(t.TempDir(), "ProgramData")
	t.Setenv("ProgramData", fakeProgramData)
	unsignedPath := filepath.Join(fakeProgramData, "Microsoft", "Windows Defender", "Platform", "4.18.0-0", "MsMpEng.exe")
	if err := os.MkdirAll(filepath.Dir(unsignedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unsignedPath, []byte("unsigned fixture body"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetTitanSignatureProbes()
	if status := titanFileSignatureStatus(unsignedPath); status == signatureStatusValid {
		t.Fatalf("unsigned fixture was reported as validly signed (%s)", status)
	}
	policy := Policy{SchemaVersion: PolicySchemaVersion, Mode: ModeBalanced, Reason: "FIND-WIN-010 unsigned check"}
	observation := Observation{
		Type:   EventPersistenceChanged,
		Object: Object{Kind: ObjectService, Name: "WinDefend", Path: `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend`, Change: "IMAGE_PATH"},
		Actor:  Actor{Image: "MsMpEng.exe", Path: unsignedPath},
	}
	if auth := Evaluate(policy, nil, observation, time.Now().UTC(), 0); auth.Status == TrustTolerated {
		t.Fatalf("unsigned binary in a canonical Defender path was tolerated: %+v", auth)
	}
}
