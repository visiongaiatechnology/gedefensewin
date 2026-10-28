// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"testing"
	"time"
)

func TestTitanFalsePositiveNormalization(t *testing.T) {
	now := time.Now().UTC()

	// 1. Per-User Service in SIMPLE and BALANCED modes
	obsService := Observation{
		Type: EventPersistenceAdded,
		Object: Object{
			Kind: ObjectService,
			Name: "MessagingService_12541b",
			Path: `HKLM\SYSTEM\CurrentControlSet\Services\MessagingService_12541b`,
		},
	}

	simplePolicy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Mode:          ModeSimple,
		Reason:        "Sovereign Desktop Simple Mode",
	}
	authSimple := Evaluate(simplePolicy, nil, obsService, now, 0)
	if authSimple.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for MessagingService_12541b in ModeSimple, got %s", authSimple.Status)
	}

	balancedPolicy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Mode:          ModeBalanced,
		Reason:        "Sovereign Enterprise Balanced Mode",
	}
	authBalanced := Evaluate(balancedPolicy, nil, obsService, now, 0)
	if authBalanced.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for MessagingService_12541b in ModeBalanced, got %s", authBalanced.Status)
	}

	// In AGGRESSIVE mode, per-user services are NOT automatically tolerated
	aggressivePolicy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Mode:          ModeAggressive,
		Reason:        "Sovereign Cyberwar Aggressive Mode",
	}
	authAggressive := Evaluate(aggressivePolicy, nil, obsService, now, 0)
	if authAggressive.Status == TrustTolerated {
		t.Fatalf("expected non-tolerated for MessagingService_12541b in ModeAggressive, got %s", authAggressive.Status)
	}

	// 2. Defender Engine / Mini-filter driver updates
	obsDriver := Observation{
		Type: EventFileCreated,
		Object: Object{
			Kind: ObjectFile,
			Name: "WdDevFlt.sys",
			Path: `C:\WINDOWS\System32\drivers\wd\WdDevFlt.sys`,
		},
		Actor: Actor{
			Image: "MsMpEng.exe",
			Path:  `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`,
		},
	}

	// In AGGRESSIVE mode: Defender update is specifically allowed!
	authDefAggressive := Evaluate(aggressivePolicy, nil, obsDriver, now, 0)
	if authDefAggressive.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for Defender driver update in ModeAggressive, got %s", authDefAggressive.Status)
	}

	// In PARANOID mode: Defender update is strictly audited/flagged!
	paranoidPolicy := Policy{
		SchemaVersion: PolicySchemaVersion,
		Mode:          ModeParanoid,
		Reason:        "Sovereign Zero-Trust Paranoid Mode",
	}
	authDefParanoid := Evaluate(paranoidPolicy, nil, obsDriver, now, 0)
	if authDefParanoid.Status == TrustTolerated {
		t.Fatalf("expected non-tolerated for Defender driver update in ModeParanoid, got %s", authDefParanoid.Status)
	}

	// 3. VS Installer localized temp DLLs
	obsTempDLL := Observation{
		Type: EventFileCreated,
		Object: Object{
			Kind: ObjectFile,
			Name: "Microsoft.Data.SqlClient.resources.dll",
			Path: `C:\Users\Masterboard\AppData\Local\Temp\fu2kx2yr.smf\resources\de\Microsoft.Data.SqlClient.resources.dll`,
		},
		Actor: Actor{
			Image: "consent.exe",
		},
	}
	authTempSimple := Evaluate(simplePolicy, nil, obsTempDLL, now, 0)
	if authTempSimple.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for temp resource DLL in ModeSimple, got %s", authTempSimple.Status)
	}

	authTempBalanced := Evaluate(balancedPolicy, nil, obsTempDLL, now, 0)
	if authTempBalanced.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for temp resource DLL in ModeBalanced, got %s", authTempBalanced.Status)
	}

	// 4. Defender Service MDCoreSvc in ModeBalanced and ModeAggressive
	obsDefService := Observation{
		Type: EventPersistenceChanged,
		Object: Object{
			Kind: ObjectService,
			Name: "MDCoreSvc",
			Path: `HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc`,
		},
		Actor: Actor{
			Image: "msmpeng.exe",
		},
	}
	authDefSvcBalanced := Evaluate(balancedPolicy, nil, obsDefService, now, 0)
	if authDefSvcBalanced.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for MDCoreSvc in ModeBalanced, got %s", authDefSvcBalanced.Status)
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
	authTask := Evaluate(balancedPolicy, nil, obsTask, now, 0)
	if authTask.Status != TrustTolerated {
		t.Fatalf("expected TrustTolerated for SvcRestartTask in ModeBalanced, got %s", authTask.Status)
	}

	// 6. Developer Build Test Artifact in Temp (e.g. winapi.test.exe)
	obsGoTest := Observation{
		Type: EventFileCreated,
		Object: Object{
			Kind: ObjectFile,
			Name: "winapi.test.exe",
			Path: `C:\Users\Masterboard\AppData\Local\Temp\go-build91238\b001\winapi.test.exe`,
		},
		Actor: Actor{
			Image: "go.exe",
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
