// STATUS: PLATIN VGT SUPREME
package titan

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FIND-WIN-010 regression: a Defender/platform tolerance may never be produced
// by an empty actor or by a name-only match.
func TestDefenderToleranceRejectsEmptyActorAndUserPaths(t *testing.T) {
	policy := Policy{SchemaVersion: PolicySchemaVersion, Mode: ModeBalanced, Reason: "FIND-WIN-010 regression"}
	now := time.Now().UTC()

	// (a) Defender service name with an ImagePath in a user-writable directory.
	obsUserPath := Observation{
		Type:   EventPersistenceChanged,
		Object: Object{Kind: ObjectService, Name: "WinDefend", Path: `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend`, Change: "IMAGE_PATH"},
		Actor:  Actor{Image: "MsMpEng.exe", Path: `C:\Users\Operator\AppData\Roaming\Fake\MsMpEng.exe`},
	}
	if auth := Evaluate(policy, nil, obsUserPath, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("Defender service with a user-path image was tolerated: %+v", auth)
	}
	if isDefenderPlatformUpdate(obsUserPath) {
		t.Fatal("name-only Defender helper accepted a user-path image")
	}

	// (b) Empty actor: never tolerated, not even with a canonical-looking name.
	obsEmptyActor := Observation{
		Type:   EventPersistenceChanged,
		Object: Object{Kind: ObjectService, Name: "WinDefend", Path: `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend`, Change: "IMAGE_PATH"},
	}
	if auth := Evaluate(policy, nil, obsEmptyActor, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("Defender service with an empty actor was tolerated: %+v", auth)
	}

	// (c) Canonical path without a valid signature: fail-closed.
	unsignedPath := filepath.Join(titanProgramDataDir(), "Microsoft", "Windows Defender", "Platform", "4.18.0-0", "MsMpEng.exe")
	withTitanSignatureVerifier(t, func(string) error { return errUnsignedInTest })
	obsUnsigned := Observation{
		Type:   EventPersistenceChanged,
		Object: Object{Kind: ObjectService, Name: "WinDefend", Path: `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend`, Change: "IMAGE_PATH"},
		Actor:  Actor{Image: "MsMpEng.exe", Path: unsignedPath},
	}
	if auth := Evaluate(policy, nil, obsUnsigned, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("unsigned binary in a canonical Defender path was tolerated: %+v", auth)
	}

	// (d) Same observation with a valid signature is tolerated, and the decision
	// stays auditable in the authorization reason.
	withTitanSignatureVerifier(t, func(path string) error {
		if strings.EqualFold(path, unsignedPath) {
			return nil
		}
		return errUnsignedInTest
	})
	authSigned := Evaluate(policy, nil, obsUnsigned, now, 0)
	if authSigned.Status != TrustTolerated {
		t.Fatalf("signed canonical Defender platform update was not tolerated: %+v", authSigned)
	}
	if !strings.Contains(authSigned.Reason, unsignedPath) || !strings.Contains(authSigned.Reason, signatureStatusValid) {
		t.Fatalf("tolerance reason does not document the evidence: %q", authSigned.Reason)
	}

	// (e) Defender service reconfiguration is tampering, not a platform update.
	obsTamper := obsUnsigned
	obsTamper.Object.Change = "START_ONLY"
	if auth := Evaluate(policy, nil, obsTamper, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("Defender service start-type change was tolerated: %+v", auth)
	}
}

func TestDefenderDriverFileToleranceRequiresCanonicalPathAndSignature(t *testing.T) {
	policy := Policy{SchemaVersion: PolicySchemaVersion, Mode: ModeBalanced, Reason: "FIND-WIN-010 driver regression"}
	now := time.Now().UTC()
	driver := Observation{
		Type:   EventFileCreated,
		Object: Object{Kind: ObjectFile, Name: "WdDevFlt.sys", Path: `C:\Windows\System32\drivers\wd\WdDevFlt.sys`},
	}
	withTitanSignatureVerifier(t, func(path string) error {
		if strings.EqualFold(path, `C:\Windows\System32\drivers\wd\WdDevFlt.sys`) {
			return nil
		}
		return errUnsignedInTest
	})
	if auth := Evaluate(policy, nil, driver, now, 0); auth.Status != TrustTolerated {
		t.Fatalf("signed canonical Defender driver was not tolerated: %+v", auth)
	}
	// A driver name outside the canonical drivers\wd path is not evidence.
	obsElsewhere := Observation{
		Type:   EventFileCreated,
		Object: Object{Kind: ObjectFile, Name: "WdDevFlt.sys", Path: `C:\Users\Operator\AppData\Local\Temp\wd\WdDevFlt.sys`},
	}
	if auth := Evaluate(policy, nil, obsElsewhere, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("Defender driver name outside the canonical path was tolerated: %+v", auth)
	}
}

// FIND-WIN-010 regression: the removed broad fallbacks must no longer tolerate
// temp artifacts by file name alone.
func TestTempArtifactToleranceRejectsNameOnlyMatches(t *testing.T) {
	policy := Policy{SchemaVersion: PolicySchemaVersion, Mode: ModeBalanced, Reason: "FIND-WIN-010 temp regression"}
	now := time.Now().UTC()
	for _, testCase := range []struct {
		name, path string
	}{
		{"foo_svc_1234.exe", `C:\Users\Operator\AppData\Local\Temp\foo_svc_1234.exe`},
		{"evil.test.exe", `C:\Users\Operator\AppData\Local\Temp\evil.test.exe`},
		{"fake.resources.dll", `C:\Users\Operator\AppData\Local\Temp\fake.resources.dll`},
		{"payload.exe", `C:\Users\Operator\AppData\Local\Temp\node_modules\payload.exe`},
	} {
		observation := Observation{Type: EventFileCreated, Object: Object{Kind: ObjectFile, Name: testCase.name,
			Path: testCase.path, FileType: classifyFile(testCase.path)}}
		if auth := Evaluate(policy, nil, observation, now, 0); auth.Status == TrustTolerated {
			t.Fatalf("name-only temp artifact %q was tolerated: %+v", testCase.path, auth)
		}
		if isInstallerSessionTempArtifact(observation) || isDevBuildTempArtifact(observation) {
			t.Fatalf("name-only temp artifact %q matched a legacy boolean helper", testCase.path)
		}
	}
}

// FIND-WIN-010 regression: an unsigned actor binary in a user directory must not
// unlock the dev/installer tolerances.
func TestTempArtifactToleranceRejectsUnverifiedActor(t *testing.T) {
	policy := Policy{SchemaVersion: PolicySchemaVersion, Mode: ModeBalanced, Reason: "FIND-WIN-010 actor regression"}
	now := time.Now().UTC()
	withTitanSignatureVerifier(t, func(string) error { return errUnsignedInTest })
	observation := Observation{
		Type: EventFileCreated,
		Object: Object{Kind: ObjectFile, Name: "Microsoft.Data.SqlClient.resources.dll",
			Path: `C:\Users\Operator\AppData\Local\Temp\crash\Microsoft.Data.SqlClient.resources.dll`},
		Actor: Actor{Image: "consent.exe", Path: `C:\Users\Operator\Downloads\consent.exe`},
	}
	if auth := Evaluate(policy, nil, observation, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("installer artifact with a user-path actor was tolerated: %+v", auth)
	}
	// Developer artifact tolerance also requires an observed actor.
	goTest := Observation{
		Type: EventFileCreated,
		Object: Object{Kind: ObjectFile, Name: "winapi.test.exe",
			Path: `C:\Users\Operator\AppData\Local\Temp\go-build123\b001\winapi.test.exe`},
		Actor: Actor{Image: "go.exe", Path: `C:\Users\Operator\Downloads\go.exe`},
	}
	if auth := Evaluate(policy, nil, goTest, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("go test artifact without an observed process actor was tolerated: %+v", auth)
	}
}
