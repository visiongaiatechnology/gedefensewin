// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

type stubContainmentExec struct {
	mu         sync.Mutex
	freezeErr  error
	resumeErr  error
	killErr    error
	frozen     []TerminationTarget
	resumed    int
	terminated int
	frozenCh   chan ContainmentProcess
}

func (s *stubContainmentExec) FreezeTree(target TerminationTarget) ([]ContainmentProcess, error) {
	if s.freezeErr != nil {
		return nil, s.freezeErr
	}
	s.mu.Lock()
	s.frozen = append(s.frozen, target)
	s.mu.Unlock()
	procs := []ContainmentProcess{
		{PID: target.PID, ParentPID: 0, Image: filepath.Base(target.ImagePath), ImagePath: target.ImagePath, CreationUnixNano: target.CreationUnixNano, ActionState: "FROZEN"},
		{PID: target.PID + 1, ParentPID: target.PID, Image: "child.exe", ImagePath: `C:\Tools\child.exe`, CreationUnixNano: target.CreationUnixNano + 1000, ActionState: "FROZEN"},
	}
	if s.frozenCh != nil {
		select {
		case s.frozenCh <- procs[0]:
		default:
		}
	}
	return procs, nil
}

func (s *stubContainmentExec) ResumeTree(processes []ContainmentProcess) (int, error) {
	if s.resumeErr != nil {
		return 0, s.resumeErr
	}
	s.mu.Lock()
	s.resumed += len(processes)
	s.mu.Unlock()
	return len(processes), nil
}

func (s *stubContainmentExec) TerminateTree(processes []ContainmentProcess) (int, error) {
	if s.killErr != nil {
		return 0, s.killErr
	}
	s.mu.Lock()
	s.terminated += len(processes)
	s.mu.Unlock()
	return len(processes), nil
}

type stubProtectionController struct {
	applyCalls atomic.Int32
}

func (s *stubProtectionController) ApplyThreatIntelligence(context.Context, string, string, int) (FirewallResult, error) {
	return FirewallResult{}, nil
}

func (s *stubProtectionController) Applications(context.Context, string, string) (ApplicationAllowResult, error) {
	return ApplicationAllowResult{}, nil
}

func (s *stubProtectionController) ApplyAppControl(context.Context, string) (AppControlResult, error) {
	return AppControlResult{State: "DEPLOYED", PolicyID: "{11111111-1111-1111-1111-111111111111}"}, nil
}

func (s *stubProtectionController) Apply(_ context.Context, mode string) (ProtectionResult, error) {
	s.applyCalls.Add(1)
	return ProtectionResult{Mode: mode, DefenderRealtime: true, ProcessTelemetry: true, WfpBlockTelemetry: true}, nil
}

func newSymbiosisTestEngine(t *testing.T) (*Engine, *stubContainmentExec, *stubProtectionController) {
	t.Helper()
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	prot := &stubProtectionController{}
	exec := &stubContainmentExec{frozenCh: make(chan ContainmentProcess, 4)}
	engine := &Engine{
		root:            filepath.Join(root, "mhx"),
		ledger:          ledger,
		protection:      prot,
		mode:            "guarded",
		analyses:        make([]Analysis, 0, maximumAnalyses),
		recentProcesses: make(map[uint32]recentProcess, 16),
		containmentExec: exec,
	}
	engine.policySettings.Store(&[]PolicySettings{DefaultPolicySettings()}[0])
	return engine, exec, prot
}

func TestDefenderOperationalStreamParsesExpandedSymbiosisEvents(t *testing.T) {
	xmlCFA := `<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>1123</EventID><TimeCreated SystemTime="2026-11-22T12:00:00Z"/></System>
  <EventData>
    <Data Name="Process Name">C:\Temp\ransom.exe</Data>
    <Data Name="Path">C:\Users\op\Documents\secret.docx</Data>
  </EventData>
</Event>`
	rec, err := parseDefenderRecord(winapi.EventLogRecord{RecordID: 9001, Channel: defenderOperationalChannel, XML: []byte(xmlCFA), TimeCreated: time.Now().UTC()})
	if err != nil {
		t.Fatalf("CFA event 1123 rejected: %v", err)
	}
	if rec.EventID != 1123 || rec.Fields["process name"] != `C:\Temp\ransom.exe` || rec.Fields["path"] != `C:\Users\op\Documents\secret.docx` {
		t.Fatalf("unexpected parsed fields: %+v", rec)
	}
	for _, id := range []string{"1118", "1119", "1121", "1122", "1124", "1125", "1126", "5004", "5013"} {
		xmlBody := `<?xml version="1.0" encoding="UTF-8"?><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>` + id + `</EventID></System><EventData><Data Name="ID">TEST</Data></EventData></Event>`
		parsed, parseErr := parseDefenderRecord(winapi.EventLogRecord{RecordID: 9002, Channel: defenderOperationalChannel, XML: []byte(xmlBody)})
		if parseErr != nil {
			t.Fatalf("valid Defender event %s was rejected: %v", id, parseErr)
		}
		if parsed.Fields["id"] != "TEST" {
			t.Fatalf("missing structured field on event %s: %+v", id, parsed.Fields)
		}
	}
}

func TestDefenderCFABlockCorrelatesProcessTriggersFreezeTreeAndFairScore(t *testing.T) {
	engine, exec, _ := newSymbiosisTestEngine(t)
	created := time.Now().UTC().Add(-10 * time.Second)
	proc := ProcessEvent{
		PID:          8810,
		ParentPID:    1000,
		CreationUTC:  created,
		TimestampUTC: time.Now().UTC(),
		Image:        "ransom.exe",
		ImagePath:    `C:\Users\op\AppData\Local\Temp\ransom.exe`,
	}
	engine.mu.Lock()
	engine.recentProcesses[proc.PID] = recentProcess{event: proc, expires: time.Now().UTC().Add(5 * time.Minute)}
	engine.mu.Unlock()

	event := defenderEvent{
		TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano),
		EventID:      1123,
		RecordID:     501,
		Message:      `Process Name=C:\Users\op\AppData\Local\Temp\ransom.exe; Path=C:\Users\op\Documents\vault.docx`,
		Fields: map[string]string{
			"process name": proc.ImagePath,
			"path":         `C:\Users\op\Documents\vault.docx`,
		},
	}
	engine.evaluateDefender(event)

	select {
	case frozen := <-exec.frozenCh:
		if frozen.PID != 8810 {
			t.Fatalf("unexpected frozen root pid: %d", frozen.PID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Defender CFA event 1123 did not trigger process-tree Freeze")
	}

	if !engine.pidHasRecentDefenderHit(8810) {
		t.Fatal("pidHasRecentDefenderHit returned false for correlated CFA process")
	}
	scoreWarn := CalculateFairScoreWithSymbiosis(proc, true, "Allowlisted Helper", false, "", false, false, false, false, true)
	if scoreWarn.Score != 60 || scoreWarn.Level != "WARNING" || scoreWarn.StrikeEvent {
		t.Fatalf("solo Defender signal expected WARNING (60), got: %+v", scoreWarn)
	}
	scoreStrike := CalculateFairScoreWithSymbiosis(
		ProcessEvent{PID: proc.PID, ImagePath: proc.ImagePath, SignerStatus: "NotSigned"},
		true, "Allowlisted Helper", false, "", false, false, false, false, true,
	)
	if !scoreStrike.StrikeEvent || scoreStrike.Score < 75 {
		t.Fatalf("Defender + unsigned signal did not escalate: %+v", scoreStrike)
	}

	// Verify reversible recovery and hard escalation states.
	deadline := time.Now().Add(2 * time.Second)
	var containments []ContainmentRecord
	for time.Now().Before(deadline) {
		containments = engine.Containments()
		if len(containments) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(containments) != 1 || containments[0].State != ContainmentFrozen || len(containments[0].Processes) != 2 {
		t.Fatalf("unexpected containment records: %+v", containments)
	}
	resumed, err := engine.ResumeContainment(containments[0].ID, "Operator verified legitimate backup tool")
	if err != nil || resumed.State != ContainmentResumed {
		t.Fatalf("ResumeContainment failed: rec=%+v err=%v", resumed, err)
	}

	// Second freeze -> hard terminate.
	second, err := engine.FreezeProcessTree(TerminationTarget{PID: 8810, CreationUnixNano: created.UnixNano(), ImagePath: proc.ImagePath, Reason: "manual escalation test"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	killed, err := engine.TerminateContainment(second.ID, "Confirmed ransomware test escalation")
	if err != nil || killed.State != ContainmentTerminated {
		t.Fatalf("TerminateContainment failed: rec=%+v err=%v", killed, err)
	}
	if status := engine.SymbiosisStatus(); status.CFABlocksObserved != 1 || status.TotalContainments != 2 || status.ActiveContainments != 0 {
		t.Fatalf("unexpected symbiosis status: %+v", status)
	}
}

func TestDefenderTamperDisableTriggersBoundedSelfHealWithCooldown(t *testing.T) {
	engine, _, prot := newSymbiosisTestEngine(t)
	event := defenderEvent{
		TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano),
		EventID:      5001,
		RecordID:     700,
		Message:      "Real-time protection disabled",
		Fields:       map[string]string{},
	}
	engine.evaluateDefender(event)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && prot.applyCalls.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if prot.applyCalls.Load() != 1 {
		t.Fatalf("expected 1 auto-heal Apply call, got %d", prot.applyCalls.Load())
	}
	// Second tamper event within cooldown must not trigger another immediate script storm.
	engine.evaluateDefender(event)
	time.Sleep(100 * time.Millisecond)
	if prot.applyCalls.Load() != 1 {
		t.Fatalf("cooldown failed to suppress duplicate auto-heal: %d", prot.applyCalls.Load())
	}
	if status := engine.SymbiosisStatus(); status.TamperEventsObserved != 2 || status.AutoHealsTriggered != 1 {
		t.Fatalf("unexpected tamper metrics: %+v", status)
	}
}

func TestContainmentRejectsProtectedOSAndSelfProcesses(t *testing.T) {
	engine, _, _ := newSymbiosisTestEngine(t)
	nowNano := time.Now().UTC().UnixNano()
	cases := []struct {
		name   string
		target TerminationTarget
	}{
		{"system-pid", TerminationTarget{PID: 4, CreationUnixNano: nowNano, ImagePath: `C:\tools\x.exe`, Reason: "test"}},
		{"self-pid", TerminationTarget{PID: uint32(os.Getpid()), CreationUnixNano: nowNano, ImagePath: `C:\tools\x.exe`, Reason: "test"}},
		{"missing-creation", TerminationTarget{PID: 9999, CreationUnixNano: 0, ImagePath: `C:\tools\x.exe`, Reason: "test"}},
		{"lsass", TerminationTarget{PID: 9999, CreationUnixNano: nowNano, ImagePath: `C:\Windows\System32\lsass.exe`, Reason: "test"}},
		{"defender", TerminationTarget{PID: 9999, CreationUnixNano: nowNano, ImagePath: `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe`, Reason: "test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := engine.FreezeProcessTree(tc.target, "test"); err == nil {
				t.Fatalf("dangerous target %s was accepted for containment", tc.name)
			}
		})
	}
}

func TestRecordTitanCompromiseClosesCrossEngineFairScoreGap(t *testing.T) {
	engine, _, _ := newSymbiosisTestEngine(t)
	created := time.Now().UTC().Add(-time.Second)
	engine.RecordTitanCompromise(TerminationTarget{
		PID:              7712,
		CreationUnixNano: created.UnixNano(),
		ImagePath:        `C:\Users\op\Downloads\dropper.exe`,
		Reason:           "Titan integrity compromise",
	})
	if !engine.pidHasRecentTitanHit(7712) {
		t.Fatal("pidHasRecentTitanHit did not retain Titan compromise signal")
	}
	warnRes := CalculateFairScoreWithSymbiosis(
		ProcessEvent{PID: 7712, ImagePath: `C:\Users\op\Downloads\dropper.exe`, SignerStatus: "NotSigned"},
		true, "Unsigned App", false, "", false, false, false, true, false,
	)
	if warnRes.Score != 65 || warnRes.Level != "WARNING" {
		t.Fatalf("Titan compromise + unsigned expected WARNING (65), got: %+v", warnRes)
	}
	strikeRes := CalculateFairScoreWithSymbiosis(
		ProcessEvent{PID: 7712, ImagePath: `C:\Users\op\Downloads\dropper.exe`, SignerStatus: "NotSigned"},
		true, "Unsigned App", true, "KD-SIG-01", false, false, false, true, false,
	)
	if !strikeRes.StrikeEvent || strikeRes.Score < 75 {
		t.Fatalf("Titan compromise + unsigned + sig did not escalate: %+v", strikeRes)
	}
}

func TestMpCmdRunOutputParserAndPathValidation(t *testing.T) {
	if got := parseMpCmdRunThreat("Scan starting...\nThreat  : Trojan:Win32/Wacatac.B!ml\nScan finished.\n"); got != "Trojan:Win32/Wacatac.B!ml" {
		t.Fatalf("unexpected parsed threat name: %q", got)
	}
	engine, _, _ := newSymbiosisTestEngine(t)
	for _, unsafePath := range []string{`\\attacker\share\evil.exe`, `relative\evil.exe`, `C:\Temp\file.txt:ads`, "C:\\Temp\\bad\x00.exe"} {
		if _, err := engine.ScanFileWithDefender(context.Background(), unsafePath); err == nil {
			t.Fatalf("unsafe oracle scan path accepted: %q", unsafePath)
		}
	}
}
