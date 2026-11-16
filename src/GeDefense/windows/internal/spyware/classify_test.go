// STATUS: PLATIN VGT SUPREME

package spyware

import (
	"testing"
	"time"
)

var testNow = time.Unix(1700000000, 0).UTC()

func TestCapabilityClassifierMatrix(t *testing.T) {
	classifier := CapabilityClassifier{
		IsAllowed: func(path string) bool {
			return path == `C:\Program Files\Microsoft\Teams\current\Teams.exe`
		},
		WorkstationLocked: false,
	}
	cases := []struct {
		name     string
		state    CapabilityState
		locked   bool
		want     bool
		severity Severity
	}{
		{"inactive", CapabilityState{Capability: CapabilityWebcam, Path: `C:\Users\Public\cam.exe`, Stop: 5}, false, false, ""},
		{"allowed stable", CapabilityState{Capability: CapabilityWebcam, Path: `C:\Program Files\Microsoft\Teams\current\Teams.exe`, Start: 100}, false, false, ""},
		{"unknown background", CapabilityState{Capability: CapabilityMicrophone, Path: `C:\Program Files\Some\App.exe`, Start: 100}, false, true, SeverityMedium},
		{"user writable", CapabilityState{Capability: CapabilityWebcam, Path: `C:\Users\Public\AppData\Local\Temp\cam.exe`, Start: 100}, false, true, SeverityHigh},
		{"locked capture", CapabilityState{Capability: CapabilityWebcam, Path: `C:\Program Files\Some\App.exe`, Start: 100}, true, true, SeverityCritical},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			classifier.WorkstationLocked = testCase.locked
			finding := classifier.Classify(testCase.state, testNow)
			if (finding != nil) != testCase.want {
				t.Fatalf("finding=%v, want %v", finding != nil, testCase.want)
			}
			if finding != nil && finding.Severity != testCase.severity {
				t.Fatalf("severity=%s, want %s", finding.Severity, testCase.severity)
			}
		})
	}
}

func TestClassifyDriverService(t *testing.T) {
	posture := SecurityPosture{VulnerableDriverBlocklistEnabled: true, HVCIEnabled: true}
	cases := []struct {
		name     string
		service  DriverService
		want     bool
		severity Severity
	}{
		{"user mode ignored", DriverService{Name: "Svc", ImagePath: `C:\Program Files\x.exe`, Type: 0x10}, false, ""},
		{"known vulnerable", DriverService{Name: "RTCore64", ImagePath: `C:\Windows\System32\drivers\RTCore64.sys`, Type: 1}, true, SeverityCritical},
		{"unsigned outside drivers", DriverService{Name: "Evil", ImagePath: `C:\Users\Public\evil.sys`, Type: 1, Signature: "NotSigned"}, true, SeverityHigh},
		{"unsigned inside drivers", DriverService{Name: "ThirdParty", ImagePath: `C:\Windows\System32\drivers\third.sys`, Type: 1, Signature: "NotSigned"}, true, SeverityMedium},
		{"signed driver", DriverService{Name: "Good", ImagePath: `C:\Windows\System32\drivers\good.sys`, Type: 1, Signature: "signed"}, false, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			finding := ClassifyDriverService(testCase.service, posture, testNow)
			if (finding != nil) != testCase.want {
				t.Fatalf("finding=%v, want %v", finding != nil, testCase.want)
			}
			if finding != nil && finding.Severity != testCase.severity {
				t.Fatalf("severity=%s, want %s", finding.Severity, testCase.severity)
			}
		})
	}
	// A known vulnerable driver on a host without its own mitigations escalates.
	finding := ClassifyDriverService(DriverService{Name: "RTCore64", ImagePath: `C:\Windows\System32\drivers\RTCore64.sys`, Type: 1},
		SecurityPosture{}, testNow)
	if finding == nil || finding.Response != "BLOCK_CANDIDATE|HOST_MITIGATIONS_DISABLED" {
		t.Fatalf("expected host mitigation escalation, got %+v", finding)
	}
}

func TestClassifyPersistence(t *testing.T) {
	cases := []struct {
		name        string
		observation PersistenceObservation
		want        bool
		severity    Severity
	}{
		{"IFEo system debugger", PersistenceObservation{Kind: PersistenceIFEO, KeyPath: "HKLM\\IFEO\\x", ValueName: "Debugger", ValueData: `C:\Windows\System32\windbg.exe`}, false, ""},
		{"IFEO attacker debugger", PersistenceObservation{Kind: PersistenceIFEO, KeyPath: "HKLM\\IFEO\\x", ValueName: "Debugger", ValueData: `C:\Users\Public\dbg.exe`}, true, SeverityCritical},
		{"AppCertDlls user path", PersistenceObservation{Kind: PersistenceAppCertDLLs, KeyPath: "HKLM\\AppCertDlls", ValueData: `C:\Users\Public\a.dll`}, true, SeverityCritical},
		{"LSA known system package", PersistenceObservation{Kind: PersistenceLSAPackages, KeyPath: "HKLM\\Lsa", ValueName: "Security Packages", ValueData: `C:\Windows\System32\kerberos.dll`}, false, ""},
		{"LSA unknown package", PersistenceObservation{Kind: PersistenceLSAPackages, KeyPath: "HKLM\\Lsa", ValueName: "Security Packages", ValueData: `C:\Users\Public\cred.dll`}, true, SeverityHigh},
		{"COM hijack user path", PersistenceObservation{Kind: PersistenceCOMHijack, KeyPath: "HKLM\\CLSID\\{x}", ValueData: `C:\Users\Public\evil.dll`}, true, SeverityHigh},
		{"BITS powershell", PersistenceObservation{Kind: PersistenceBITSCallback, KeyPath: "BITS", ValueData: `powershell.exe -enc AAAA`}, true, SeverityHigh},
		{"BITS benign", PersistenceObservation{Kind: PersistenceBITSCallback, KeyPath: "BITS", ValueData: `C:\Program Files\App\notify.exe`}, false, ""},
		{"WMI subscription", PersistenceObservation{Kind: PersistenceWMISubscription, KeyPath: "WMI", ValueData: "CommandLineEventConsumer"}, true, SeverityHigh},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			finding := ClassifyPersistence(testCase.observation)
			if (finding != nil) != testCase.want {
				t.Fatalf("finding=%v, want %v", finding != nil, testCase.want)
			}
			if finding != nil && finding.Severity != testCase.severity {
				t.Fatalf("severity=%s, want %s", finding.Severity, testCase.severity)
			}
		})
	}
}

func TestClassifyLSASSAccess(t *testing.T) {
	if finding := ClassifyLSASSAccess(0x0008, `C:\Users\Public\evil.exe`, "NotSigned", testNow); finding != nil {
		t.Fatal("non-VM_READ access must not be a finding")
	}
	if finding := ClassifyLSASSAccess(ProcessVMRead, `C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe`, "microsoft", testNow); finding != nil {
		t.Fatal("allowlisted Microsoft reader must not be a finding")
	}
	finding := ClassifyLSASSAccess(ProcessVMRead, `C:\Users\Public\mini.exe`, "NotSigned", testNow)
	if finding == nil || finding.Severity != SeverityCritical {
		t.Fatalf("expected critical LSASS finding, got %+v", finding)
	}
	if finding := ClassifyLSASSAccess(ProcessVMRead, `C:\Windows\System32\custom.exe`, "NotSigned", testNow); finding == nil {
		t.Fatal("unsiged non-allowlisted reader must be a finding")
	}
}

type recordingLedger struct {
	entries int
}

func (ledger *recordingLedger) Append(kind, detail, result string) error {
	ledger.entries++
	return nil
}

func TestEngineDeduplicatesAndBounds(t *testing.T) {
	ledger := &recordingLedger{}
	engine := New(Settings{Enabled: true, Capability: true, BYOVD: true}, ledger)
	engine.now = func() time.Time { return testNow }

	state := CapabilityState{Capability: CapabilityWebcam, Path: `C:\Program Files\Some\App.exe`, Start: 100}
	if recorded := engine.HandleCapabilityStates([]CapabilityState{state}, false); len(recorded) != 1 {
		t.Fatalf("first observation recorded %d findings, want 1", len(recorded))
	}
	if recorded := engine.HandleCapabilityStates([]CapabilityState{state}, false); len(recorded) != 0 {
		t.Fatalf("duplicate observation recorded %d findings, want 0", len(recorded))
	}
	if engine.Status().Findings != 1 {
		t.Fatalf("status findings = %d, want 1", engine.Status().Findings)
	}
	if ledger.entries != 1 {
		t.Fatalf("ledger entries = %d, want 1", ledger.entries)
	}

	// Dedupe window expiry re-records the same asset rather than hiding it.
	testNow = testNow.Add(findingDedupeTTL + time.Minute)
	engine.now = func() time.Time { return testNow }
	if recorded := engine.HandleCapabilityStates([]CapabilityState{state}, false); len(recorded) != 1 {
		t.Fatalf("post-window observation recorded %d findings, want 1", len(recorded))
	}

	for index := 0; index < MaxFindings+64; index++ {
		path := `C:\Users\Public\AppData\Local\Temp\payload-` + string(rune('a'+index%26)) + string(rune('a'+index/26%26)) + `.exe`
		testNow = testNow.Add(findingDedupeTTL + time.Minute)
		engine.now = func() time.Time { return testNow }
		engine.HandleCapabilityStates([]CapabilityState{{Capability: CapabilityMicrophone, Path: path, Start: 100}}, false)
	}
	if got := len(engine.Findings(MaxFindings * 2)); got > MaxFindings {
		t.Fatalf("findings list unbounded: %d > %d", got, MaxFindings)
	}
}

func TestEngineRespectsDisabledSensors(t *testing.T) {
	engine := New(Settings{Enabled: false}, nil)
	if engine.HandleCapabilityStates([]CapabilityState{{Capability: CapabilityWebcam, Path: `C:\Temp\a.exe`, Start: 1}}, true) != nil {
		t.Fatal("disabled engine must not record findings")
	}
	if engine.HandleDriverService(DriverService{Name: "RTCore64", ImagePath: `C:\Windows\System32\drivers\RTCore64.sys`, Type: 1}, SecurityPosture{}) != nil {
		t.Fatal("disabled engine must not classify drivers")
	}
}
