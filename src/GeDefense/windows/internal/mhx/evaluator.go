// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	suspiciousTokens = []string{"invoke-expression", " iex ", "downloadstring", "downloadfile", "system.net.webclient", "invoke-webrequest", "start-bitstransfer", "frombase64string", "virtualalloc", "writeprocessmemory", "createremotethread", "amsiutils", "amsiscanbuffer", "reflection.assembly", "dllimport", "minidumpwritedump", "sekurlsa", "rundll32", "regsvr32", "mshta"}
	parserPattern    = regexp.MustCompile(`(?i)(?:system\.management\.automation\.)?language\.parser\s*\]?[\s:]*::\s*parse(?:input|file)\s*\(`)
)

type Evaluator struct{}

func (Evaluator) Analyze(event ProcessEvent) Analysis {
	now := event.TimestampUTC.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result := Analysis{TimestampUTC: now, InitialSeverity: SeverityLow, EffectiveSeverity: SeverityLow, Disposition: DispositionAudit, Detection: "Process start telemetry", Classification: "UNCLASSIFIED", ConfidenceBasis: 5000, PID: event.PID, ParentPID: event.ParentPID, Image: event.Image, Parent: event.ParentImage, Signer: event.SignerSubject, Signals: []string{}}
	result.ID = analysisID(event, now)
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
	result.DecodedPayload = truncate(payload, 8192)
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
	if knownCodexParser(event, payload) {
		result.EffectiveSeverity = SeverityInformational
		result.Disposition = DispositionAllow
		result.Classification = "KNOWN BENIGN"
		result.Identified = "OpenAI Codex PowerShell AST Parser"
		result.Purpose = "Windows command-safety AST parsing"
		result.ConfidenceBasis = 9990
		result.Signals = append(result.Signals, "provenance.openai-signed", "purpose.ast-parse-only")
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
	trustedNames := map[string]struct{}{"powershell.exe": {}, "pwsh.exe": {}, "cmd.exe": {}, "cscript.exe": {}, "wscript.exe": {}, "mshta.exe": {}, "rundll32.exe": {}, "regsvr32.exe": {}, "wmic.exe": {}, "certutil.exe": {}, "bitsadmin.exe": {}, "vssadmin.exe": {}, "schtasks.exe": {}}
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

func knownCodexParser(event ProcessEvent, payload string) bool {
	parentImage, signerState, signer := event.ParentImage, event.ParentSigState, event.ParentSigner
	if parentImage == "" && len(event.Ancestry) > 0 {
		parentImage, signerState, signer = event.Ancestry[0].Image, event.Ancestry[0].SignerStatus, event.Ancestry[0].Signer
	}
	parent := strings.ToLower(filepath.Base(parentImage))
	if parent != "codex.exe" || !strings.EqualFold(signerState, "Valid") {
		return false
	}
	if !strings.Contains(strings.ToLower(signer), "openai opco") {
		return false
	}
	return parserPattern.MatchString(payload)
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
