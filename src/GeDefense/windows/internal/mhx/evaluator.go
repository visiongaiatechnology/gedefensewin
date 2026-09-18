// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var suspiciousTokens = []string{"invoke-expression", " iex ", "downloadstring", "downloadfile", "system.net.webclient", "invoke-webrequest", "start-bitstransfer", "frombase64string", "virtualalloc", "writeprocessmemory", "createremotethread", "amsiutils", "amsiscanbuffer", "reflection.assembly", "dllimport", "minidumpwritedump", "sekurlsa", "rundll32", "regsvr32", "mshta"}

type Evaluator struct{}

func (Evaluator) Analyze(event ProcessEvent) (result Analysis) {
	now := event.TimestampUTC.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result = Analysis{TimestampUTC: now, InitialSeverity: SeverityLow, EffectiveSeverity: SeverityLow, Disposition: DispositionAudit, Detection: "Process start telemetry", Classification: "UNCLASSIFIED", ConfidenceBasis: 5000, PID: event.PID, CreationUTC: event.CreationUTC, ParentPID: event.ParentPID, Image: event.Image, Parent: event.ParentImage, Signer: event.SignerSubject, Signals: []string{}}
	result.ID = analysisID(event, now)
	defer func() {
		result.SignalCategories = signalCategories(result.Signals)
		result.ResponseAuthority = responseAuthority(result.Disposition, result.Signals, result.SignalCategories)
	}()
	rawSignals := rawBehaviorSignals(event)
	result.Signals = append(result.Signals, rawSignals...)
	payload, encoding, encoded, decodeErr := DecodePowerShellCommand(event.CommandLine)
	if !encoded {
		if len(rawSignals) > 0 {
			result.InitialSeverity = SeverityHigh
			result.EffectiveSeverity = SeverityHigh
			result.Disposition = DispositionBlock
			result.Detection = "Suspicious living-off-the-land process behavior"
			result.Classification = "SUSPICIOUS"
			result.ConfidenceBasis = min(9900, 8200+len(rawSignals)*300)
			if containsCritical(rawSignals) {
				result.EffectiveSeverity = SeverityCritical
			}
		}
		return result
	}
	result.InitialSeverity = SeverityHigh
	result.EffectiveSeverity = SeverityHigh
	result.Disposition = DispositionBlock
	result.Detection = "Suspicious encoded or in-memory command line"
	result.Signals = append(result.Signals, "powershell.encoded-command")
	if decodeErr != nil {
		result.Classification = "MALFORMED ENCODED COMMAND"
		result.ConfidenceBasis = 9000
		result.Signals = append(result.Signals, "decode.failed")
		return result
	}
	result.DecodedEncoding = encoding
	digest := sha256.Sum256([]byte(payload))
	result.DecodedSHA256 = hex.EncodeToString(digest[:])
	result.DecodedBytes = len(payload)
	riskSignals := append([]string(nil), rawSignals...)
	contentRisk := contentSignals(payload)
	riskSignals = append(riskSignals, contentRisk...)
	result.Signals = append(result.Signals, contentRisk...)
	if len(riskSignals) > 0 {
		result.Classification = "SUSPICIOUS"
		result.ConfidenceBasis = min(9900, 8400+len(riskSignals)*250)
		if containsCritical(riskSignals) {
			result.EffectiveSeverity = SeverityCritical
		}
		return result
	}
	result.Classification = "UNRESOLVED ENCODED COMMAND"
	result.ConfidenceBasis = 7600
	return result
}

func rawBehaviorSignals(event ProcessEvent) []string {
	image := strings.ToLower(filepath.Base(event.Image))
	command := " " + strings.ToLower(strings.Join(strings.Fields(event.CommandLine), " ")) + " "
	signals := make([]string, 0, 6)
	trustedNames := map[string]struct{}{"powershell.exe": {}, "pwsh.exe": {}, "cmd.exe": {}, "cscript.exe": {}, "wscript.exe": {}, "mshta.exe": {}, "rundll32.exe": {}, "regsvr32.exe": {}, "wmic.exe": {}, "certutil.exe": {}, "bitsadmin.exe": {}, "vssadmin.exe": {}, "schtasks.exe": {}, "reg.exe": {}, "sc.exe": {}, "msiexec.exe": {}, "installutil.exe": {}, "msbuild.exe": {}, "regsvcs.exe": {}, "regasm.exe": {}, "forfiles.exe": {}}
	if _, target := trustedNames[image]; target {
		path := strings.ToLower(event.ImagePath)
		if path != "" && (strings.Contains(path, `\temp\`) || strings.Contains(path, `\appdata\`)) {
			signals = append(signals, "provenance.user-writable-lolbin")
		}
		if event.SignerStatus != "" && !strings.EqualFold(event.SignerStatus, "Valid") {
			signals = append(signals, "provenance.invalid-lolbin-signature")
		}
	}
	patterns := []struct{ token, signal string }{
		{" downloadstring", "lolbin.download-string"}, {" invoke-expression", "lolbin.dynamic-execution"}, {" iex ", "lolbin.dynamic-execution"},
		{" -urlcache", "lolbin.certutil-remote-fetch"}, {" /transfer", "lolbin.bitsadmin-transfer"},
		{"mshta http", "lolbin.mshta-remote"}, {"mshta.exe http", "lolbin.mshta-remote"}, {"scrobj.dll", "lolbin.regsvr32-scriptlet"},
		{"rundll32 javascript:", "lolbin.rundll32-javascript"}, {"vssadmin delete shadows", "impact.shadow-copy-delete"},
		{"wmic process call create", "lolbin.wmi-process-create"}, {" /create", "persistence.scheduled-task-create"}, {" -windowstyle hidden", "evasion.hidden-window"}, {" -w hidden", "evasion.hidden-window"},
		{" -executionpolicy bypass", "evasion.execution-policy-bypass"}, {" -ep bypass", "evasion.execution-policy-bypass"},
		{"comsvcs.dll", "credential.minidump-comsvcs"}, {"lsass", "credential.lsass-access"},
		{"reg add", "persistence.registry-write"}, {" currentversion\\run", "persistence.registry-run-key"},
		{"sc create", "persistence.service-create"}, {"msiexec /i http", "lolbin.msiexec-remote"},
		{"installutil", "lolbin.installutil"}, {"msbuild", "lolbin.msbuild"},
	}
	for _, pattern := range patterns {
		if strings.Contains(command, pattern.token) {
			signals = appendUnique(signals, pattern.signal)
		}
	}
	riskyAncestors := map[string]struct{}{"winword.exe": {}, "excel.exe": {}, "powerpnt.exe": {}, "outlook.exe": {}, "acrord32.exe": {}, "msedge.exe": {}, "chrome.exe": {}, "firefox.exe": {}}
	for _, ancestor := range event.Ancestry {
		if _, risky := riskyAncestors[strings.ToLower(filepath.Base(ancestor.Image))]; risky {
			signals = appendUnique(signals, "lineage.user-content-to-lolbin")
			break
		}
	}
	return signals
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func contentSignals(payload string) []string {
	normalized := " " + strings.ToLower(strings.Join(strings.Fields(payload), " ")) + " "
	signals := make([]string, 0, 4)
	for _, token := range suspiciousTokens {
		if strings.Contains(normalized, token) {
			signals = append(signals, "payload."+strings.TrimSpace(token))
		}
	}
	return signals
}

func signalCategories(signals []string) []string {
	seen := make(map[string]struct{}, 8)
	result := make([]string, 0, 8)
	for _, signal := range signals {
		category := signal
		if index := strings.IndexByte(signal, '.'); index > 0 {
			category = signal[:index]
		}
		if _, exists := seen[category]; exists {
			continue
		}
		seen[category] = struct{}{}
		result = append(result, category)
	}
	sort.Strings(result)
	return result
}

func responseAuthority(disposition Disposition, signals, categories []string) bool {
	if disposition != DispositionBlock {
		return false
	}
	if containsCritical(signals) {
		return true
	}
	independent := 0
	for _, category := range categories {
		switch category {
		case "decode", "purpose":
			continue
		default:
			independent++
		}
	}
	return independent >= 2
}

func containsCritical(signals []string) bool {
	for _, signal := range signals {
		if strings.Contains(signal, "amsi") || strings.Contains(signal, "writeprocessmemory") || strings.Contains(signal, "createremotethread") || strings.Contains(signal, "minidump") || strings.Contains(signal, "sekurlsa") {
			return true
		}
	}
	return false
}

func analysisID(event ProcessEvent, timestamp time.Time) string {
	digest := sha256.Sum256([]byte(event.ImagePath + "\x00" + event.CommandLine + "\x00" + timestamp.Format(time.RFC3339Nano)))
	return hex.EncodeToString(digest[:16])
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}
