package titan

import (
	"testing"
	"time"
)

func TestOwnerProcessChainToleratesIngressButNotSystemPersistence(t *testing.T) {
	policy := DefaultPolicy("test owner policy")
	policy.Mode = ModeStrict
	policy.OwnerProcessImages = []string{`C:\Tools\DeepSeek Harness.exe`}
	now := time.Now().UTC()

	ingress := Observation{
		Type:   EventFileCreated,
		Object: Object{Kind: ObjectFile, Path: `C:\Users\Owner\AppData\Local\Temp\work\script.ps1`},
		Actor: Actor{
			PID:                100,
			Image:              "powershell.exe",
			ProcessChain:       []string{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Tools\DeepSeek Harness.exe`},
			CorrelationQuality: CorrelationTemporal,
		},
	}
	auth := Evaluate(policy, nil, ingress, now, 0)
	if auth.Status != TrustTolerated || auth.NeedsReview {
		t.Fatalf("owner toolchain ingress status=%s review=%t, want TOLERATED without review", auth.Status, auth.NeedsReview)
	}

	persistence := Observation{
		Type:   EventPersistenceAdded,
		Object: Object{Kind: ObjectScheduledTask, Path: `C:\Windows\System32\Tasks\Microsoft\Windows\Windows Defender\Scan`},
		Actor: Actor{
			PID:                101,
			Image:              "powershell.exe",
			ProcessChain:       []string{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Tools\DeepSeek Harness.exe`},
			CorrelationQuality: CorrelationTemporal,
		},
	}
	auth = Evaluate(policy, nil, persistence, now, 0)
	if auth.Status == TrustTolerated {
		t.Fatalf("owner toolchain must not tolerate persistence changes: %+v", auth)
	}
}

func TestProcessContextSkipsConsoleHosts(t *testing.T) {
	now := time.Now().UTC()
	engine := &Engine{processes: []processObservation{
		{ObservedUTC: now, PID: 10, Image: "conhost.exe", Chain: []string{`C:\Windows\System32\conhost.exe`}},
		{ObservedUTC: now.Add(-time.Second), PID: 11, Image: "powershell.exe", Chain: []string{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Tools\DeepSeek Harness.exe`}},
	}}
	actor, ok := engine.processContext(now)
	if !ok {
		t.Fatal("expected a non-console actor")
	}
	if actor.PID != 11 || actor.Image != "powershell.exe" {
		t.Fatalf("actor=%+v, want the observed PowerShell process", actor)
	}
	if len(actor.ProcessChain) != 2 || actor.ProcessChain[1] != `C:\Tools\DeepSeek Harness.exe` {
		t.Fatalf("process chain=%v", actor.ProcessChain)
	}
}
