// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTitanFalsePositiveNormalization(t *testing.T) {
	// Every tolerance below rests on deterministic evidence now (FIND-WIN-010):
	// canonical path plus (where required) a valid Authenticode signature. The
	// verifier is injected so the fixtures stay platform-independent; the
	// production binding to winapi.VerifyAuthenticode is fail-closed.
	withTitanSignatureVerifier(t, alwaysValidSignatureVerifier)
	defenderImage := filepath.Join(titanProgramDataDir(), "Microsoft", "Windows Defender", "Platform", "4.18.24090.11-0", "MsMpEng.exe")
	svchost := `C:\Windows\System32\svchost.exe`
	now := time.Now().UTC()

	simplePolicy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Mode:          ModeSimple,
		Reason:        "Sovereign Desktop Simple Mode",
	}
	balancedPolicy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Mode:          ModeBalanced,
		Reason:        "Sovereign Enterprise Balanced Mode",
	}
	aggressivePolicy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Mode:          ModeAggressive,
		Reason:        "Sovereign Cyberwar Aggressive Mode",
	}
	paranoidPolicy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Mode:          ModeParanoid,
		Reason:        "Sovereign Zero-Trust Paranoid Mode",
	}

	// 1. Per-User Service in SIMPLE and BALANCED modes. The tolerance requires
	// canonical System32\svchost.exe evidence, not just a matching name.
	obsService := Observation{
		Type: EventPersistenceAdded,
		Object: Object{
			Kind: ObjectService,
			Name: "MessagingService_12541b",
			Path: `HKLM\SYSTEM\CurrentControlSet\Services\MessagingService_12541b`,
		},
		Actor: Actor{Image: "svchost.exe", Path: svchost, CorrelationQuality: CorrelationNone},
	}
	if authSimple := Evaluate(simplePolicy, nil, obsService, now, 0); authSimple.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for MessagingService_12541b in ModeSimple, got %s", authSimple.Status)
	}
	if authBalanced := Evaluate(balancedPolicy, nil, obsService, now, 0); authBalanced.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for MessagingService_12541b in ModeBalanced, got %s", authBalanced.Status)
	}
	// In AGGRESSIVE mode, per-user services are NOT automatically tolerated
	if authAggressive := Evaluate(aggressivePolicy, nil, obsService, now, 0); authAggressive.Status == TrustTolerated {
		t.Fatalf("expected non-tolerated for MessagingService_12541b in ModeAggressive, got %s", authAggressive.Status)
	}
	// A name-only match with a user-path image is never tolerated.
	obsFakeService := obsService
	obsFakeService.Actor = Actor{Image: "svchost.exe", Path: `C:\Users\Operator\AppData\Local\Temp\svchost.exe`, CorrelationQuality: CorrelationNone}
	if auth := Evaluate(balancedPolicy, nil, obsFakeService, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("user-path svchost image was tolerated as per-user service: %+v", auth)
	}
	// A random "<name>_<hex>" service is not tolerated by name pattern alone.
	obsRandomService := obsService
	obsRandomService.Object.Name = "TotallyRandomSvc_1234abcd"
	obsRandomService.Object.Path = `HKLM\SYSTEM\CurrentControlSet\Services\TotallyRandomSvc_1234abcd`
	obsRandomService.Actor = Actor{}
	if auth := Evaluate(balancedPolicy, nil, obsRandomService, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("random service name pattern was tolerated: %+v", auth)
	}

	// 2. Defender Engine / Mini-filter driver updates: canonical path AND valid
	// signature are required; the actor, when observed, must be a Defender updater.
	obsDriver := Observation{
		Type: EventFileCreated,
		Object: Object{
			Kind: ObjectFile,
			Name: "WdDevFlt.sys",
			Path: `C:\Windows\System32\drivers\wd\WdDevFlt.sys`,
		},
		Actor: Actor{
			Image: "MsMpEng.exe",
			Path:  defenderImage,
		},
	}
	if auth := Evaluate(aggressivePolicy, nil, obsDriver, now, 0); auth.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for Defender driver update in ModeAggressive, got %s", auth.Status)
	}
	// In PARANOID mode: Defender update is strictly audited/flagged!
	if auth := Evaluate(paranoidPolicy, nil, obsDriver, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("expected non-tolerated for Defender driver update in ModeParanoid, got %s", auth.Status)
	}

	// 3. VS Installer localized temp DLLs: the actor must be an evidenced,
	// signed installer component in a trusted tool path.
	obsTempDLL := Observation{
		Type: EventFileCreated,
		Object: Object{
			Kind: ObjectFile,
			Name: "Microsoft.Data.SqlClient.resources.dll",
			Path: `C:\Users\operator\AppData\Local\Temp\fu2kx2yr.smf\resources\de\Microsoft.Data.SqlClient.resources.dll`,
		},
		Actor: Actor{
			Image: "consent.exe",
			Path:  `C:\Windows\System32\consent.exe`,
		},
	}
	if auth := Evaluate(simplePolicy, nil, obsTempDLL, now, 0); auth.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for temp resource DLL in ModeSimple, got %s", auth.Status)
	}
	if auth := Evaluate(balancedPolicy, nil, obsTempDLL, now, 0); auth.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for temp resource DLL in ModeBalanced, got %s", auth.Status)
	}

	// 4. Defender Service MDCoreSvc in ModeBalanced and ModeAggressive
	obsDefService := Observation{
		Type: EventPersistenceChanged,
		Object: Object{
			Kind:   ObjectService,
			Name:   "MDCoreSvc",
			Path:   `HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc`,
			Change: "IMAGE_PATH",
		},
		Actor: Actor{
			Image: "MsMpEng.exe",
			Path:  defenderImage,
		},
	}
	if auth := Evaluate(balancedPolicy, nil, obsDefService, now, 0); auth.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for MDCoreSvc in ModeBalanced, got %s", auth.Status)
	}
	// Disabling/Start-type changes of a Defender service are tampering, not a
	// platform update and must never be tolerated.
	obsDefTamper := obsDefService
	obsDefTamper.Object.Change = "START_ONLY"
	if auth := Evaluate(balancedPolicy, nil, obsDefTamper, now, 0); auth.Status == TrustTolerated {
		t.Fatalf("Defender service start-type tamper was tolerated: %+v", auth)
	}

	// 5. Windows Scheduled Maintenance Task (e.g. SvcRestartTask / Defender Scan)
	obsTask := Observation{
		Type: EventPersistenceChanged,
		Object: Object{
			Kind: ObjectScheduledTask,
			Name: "SvcRestartTask",
			Path: `C:\Windows\System32\Tasks\Microsoft\Windows\AppID\SvcRestartTask`,
		},
	}
	if auth := Evaluate(balancedPolicy, nil, obsTask, now, 0); auth.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for SvcRestartTask in ModeBalanced, got %s", auth.Status)
	}

	// 6. Developer Build Test Artifact in Temp (e.g. winapi.test.exe) requires a
	// process that Titan actually observed, not just a matching file name.
	obsGoTest := Observation{
		Type: EventFileCreated,
		Object: Object{
			Kind: ObjectFile,
			Name: "winapi.test.exe",
			Path: `C:\Users\operator\AppData\Local\Temp\go-build91238\b001\winapi.test.exe`,
		},
		Actor: Actor{
			Image:              "go.exe",
			Path:               `C:\Program Files\Go\bin\go.exe`,
			CorrelationQuality: CorrelationTemporal,
		},
	}
	autoQPolicy := Policy{
		SchemaVersion:  PolicySchemaVersion,
		Mode:           ModeBalanced,
		AutoQuarantine: true,
		Reason:         "Balanced with auto quarantine",
	}
	authGoTest := Evaluate(autoQPolicy, nil, obsGoTest, now, 0)
	if authGoTest.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for winapi.test.exe in ModeBalanced, got %s", authGoTest.Status)
	}
	if authGoTest.AutoQuarantine {
		t.Fatalf("expected AutoQuarantine == false for developer test binary")
	}
}

func TestTitanPolicyStoreKillerdomCorrelation(t *testing.T) {
	tempDir := t.TempDir()
	storePath := tempDir + `\policy.json`

	store, err := OpenPolicyStore(storePath)
	if err != nil {
		t.Fatalf("OpenPolicyStore: %v", err)
	}

	// Test Setting Mode
	p, err := store.SetMode(ModeAggressive, false, "Activating Aggressive Mode for test")
	if err != nil {
		t.Fatalf("SetMode Aggressive: %v", err)
	}
	if p.Mode != ModeAggressive {
		t.Fatalf("expected ModeAggressive, got %s", p.Mode)
	}

	// Test Killerdom correlation
	p, err = store.SetCorrelationWithKillerdom(true, "Enabling Killerdom correlation bridge")
	if err != nil {
		t.Fatalf("SetCorrelationWithKillerdom: %v", err)
	}
	if !p.CorrelateWithKillerdom {
		t.Fatalf("expected CorrelateWithKillerdom == true")
	}

	// Reopen store to verify persistence
	store2, err := OpenPolicyStore(storePath)
	if err != nil {
		t.Fatalf("OpenPolicyStore reopen: %v", err)
	}
	if !store2.Current().CorrelateWithKillerdom {
		t.Fatalf("expected persisted CorrelateWithKillerdom == true")
	}
	if store2.Current().Mode != ModeAggressive {
		t.Fatalf("expected persisted Mode == ModeAggressive, got %s", store2.Current().Mode)
	}
}
