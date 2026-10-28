// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var suspiciousTokens = []string{"invoke-expression", " iex ", "downloadstring", "downloadfile", "system.net.webclient", "invoke-webrequest", "start-bitstransfer", "frombase64string", "virtualalloc", "writeprocessmemory", "createremotethread", "amsiutils", "amsiscanbuffer", "reflection.assembly", "dllimport", "minidumpwritedump", "sekurlsa", "rundll32", "regsvr32", "mshta"}

const (
	// encodedCommandSignal marks a process whose command line carries an
	// -EncodedCommand payload. It is authoritative on its own: the block is
	// caused by a first-class execution indicator, not a contextual
	// annotation, so host response is authorized even when the payload cannot
	// be classified (malformed or unresolved).
	encodedCommandSignal = "powershell.encoded-command"
	// renamedLolbinSignal marks a PE whose OriginalFilename version resource
	// names a tracked living-off-the-land binary while the running image
	// basename differs: a renamed or masqueraded system binary.
	renamedLolbinSignal = "provenance.renamed-lolbin"
)

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
	// -EncodedCommand is a PowerShell parameter. Applying the parser to every
	// process command line misclassified legitimate flags such as `go list -e`
	// or `node -e` as malformed encoded payloads and terminated them.
	payload, encoding, encoded, decodeErr := "", "", false, error(nil)
	if isPowerShellHost(event.Image) {
		payload, encoding, encoded, decodeErr = DecodePowerShellCommand(event.CommandLine)
	}
	if !encoded {
		if len(rawSignals) > 0 {
			strong := hasStrongBehaviorSignal(rawSignals)
			independent := len(signalCategories(rawSignals))
			if strong || independent >= 2 {
				result.InitialSeverity = SeverityHigh
				result.EffectiveSeverity = SeverityHigh
				result.Disposition = DispositionBlock
				result.Detection = "Suspicious living-off-the-land process behavior"
				result.Classification = "SUSPICIOUS"
				result.ConfidenceBasis = min(9900, 8200+len(rawSignals)*300)
				if containsCritical(rawSignals) {
					result.EffectiveSeverity = SeverityCritical
				}
			} else {
				// A single weak contextual signal is common in legitimate admin
				// and installer traffic (for example a Microsoft-signed
				// PowerShell process with a transient invalid signature read, or
				// a script launched with -ExecutionPolicy Bypass). Keep it for
				// review but never claim a block or raise a block toast.
				result.InitialSeverity = SeverityMedium
				result.EffectiveSeverity = SeverityMedium
				result.Disposition = DispositionAudit
				result.Detection = "Review-only living-off-the-land behavior"
				result.Classification = "REVIEW ONLY"
				result.ConfidenceBasis = 5200
			}
		}
		return result
	}
	result.InitialSeverity = SeverityHigh
	result.EffectiveSeverity = SeverityHigh
	result.Disposition = DispositionBlock
	result.Detection = "Suspicious encoded or in-memory command line"
	result.Signals = append(result.Signals, encodedCommandSignal)
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

// isPowerShellHost reports whether the image is a PowerShell host that can
// actually interpret -EncodedCommand. Other binaries (go, node, grep, ...) also
// accept a bare -e flag and must not be parsed with PowerShell semantics.
func isPowerShellHost(image string) bool {
	switch strings.ToLower(filepath.Base(strings.TrimSpace(image))) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return true
	default:
		return false
	}
}

func rawBehaviorSignals(event ProcessEvent) []string {
	image := strings.ToLower(filepath.Base(event.Image))
	command := normalizeBehaviorText(normalizeCommandLineText(event.CommandLine))
	signals := make([]string, 0, 7)
	// The PE OriginalFilename resource survives a file rename. When it names a
	// tracked LOLBin but the image basename does not, the running file is a
	// renamed or masqueraded system binary; that provenance evidence is
	// actionable regardless of the command line it was started with.
	original := strings.ToLower(filepath.Base(strings.TrimSpace(event.OriginalImageName)))
	if original != "" && original != image && isKnownLolbinImage(original) {
		signals = appendUnique(signals, renamedLolbinSignal)
	}
	if isKnownLolbinImage(image) {
		path := strings.ToLower(event.ImagePath)
		if path != "" && (strings.Contains(path, `\temp\`) || strings.Contains(path, `\appdata\`)) {
			signals = append(signals, "provenance.user-writable-lolbin")
		}
		if event.SignerStatus != "" && !strings.EqualFold(event.SignerStatus, "Valid") && !isSystemLolbinPath(event.ImagePath) && event.ParentPID != 0 {
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

func isSystemLolbinPath(value string) bool {
	path := strings.ToLower(filepath.Clean(strings.TrimSpace(value)))
	if path == "" || path == "." {
		return false
	}
	windows := strings.ToLower(os.Getenv("SystemRoot"))
	if windows == "" {
		windows = `c:\windows`
	}
	return strings.HasPrefix(path, filepath.Join(windows, "system32")+string(os.PathSeparator)) ||
		strings.HasPrefix(path, filepath.Join(windows, "syswow64")+string(os.PathSeparator))
}

// hasStrongBehaviorSignal separates independent, actionable evidence from weak
// contextual annotations. A single execution-policy bypass or a transient
// signature-read failure is not enough to claim a block.
func hasStrongBehaviorSignal(signals []string) bool {
	for _, signal := range signals {
		switch signal {
		case "provenance.invalid-lolbin-signature", "evasion.execution-policy-bypass", "evasion.hidden-window":
			continue
		default:
			return true
		}
	}
	return false
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
	normalized := normalizeBehaviorText(payload)
	if normalized == "" {
		return nil
	}
	signals := make([]string, 0, 4)
	for _, token := range suspiciousTokens {
		if strings.Contains(normalized, token) {
			signals = append(signals, "payload."+strings.TrimSpace(token))
		}
	}
	return signals
}

// normalizeCommandLineText turns a raw Windows command line into the argument
// line the started process receives. Windows command-line grouping is resolved
// with the same splitter as the encoded-command decoder, so embedded code such
// as -Command "& \"ie\"+\"x\"" is exposed without its transport quoting. A
// malformed command line (unterminated quote, embedded NUL) falls back to the
// raw text so obfuscation analysis still sees every byte.
func normalizeCommandLineText(commandLine string) string {
	args, err := splitWindowsCommandLine(commandLine)
	if err != nil || len(args) == 0 {
		return commandLine
	}
	return strings.Join(args, " ")
}

// behaviorTokenSeparators turns command separators and grouping punctuation
// into token boundaries. Characters that can belong to a legitimate token
// (letters, digits, '.', '-', '_', ':', '\', '/') are deliberately preserved so
// paths and URLs in benign administration command lines keep their shape.
var behaviorTokenSeparators = strings.NewReplacer(
	`"`, " ", `'`, " ",
	"(", " ", ")", " ", "{", " ", "}", " ", "[", " ", "]", " ",
	";", " ", "|", " ", "&", " ", ",", " ", "+", " ", "=", " ",
)

// normalizeBehaviorText produces the canonical space-delimited form used for
// behavior-token matching. It defeats the common command-line obfuscation
// primitives without inventing tokens:
//
//   - PowerShell backtick escapes and cmd caret escapes are removed, so
//     "Invoke-Ex`pression" and "Invoke-Ex^pression" read as
//     "invoke-expression";
//   - adjacent quoted string literals joined by '+' are concatenated, so
//     `"Invoke-"+"Expression"` reads as "invoke-expression" and
//     `& ("ie"+"x")` reads as "& iex";
//   - quote characters are stripped;
//   - punctuation is rewritten to token boundaries, so "iex(...)" exposes the
//     standalone " iex " token;
//   - whitespace is collapsed and the result is padded with single spaces.
//
// The input is lowercased first, so mixed-case obfuscation is folded as well.
func normalizeBehaviorText(value string) string {
	text := strings.ToLower(value)
	text = strings.ReplaceAll(text, `\"`, `"`)
	text = strings.NewReplacer("`", "", "^", "").Replace(text)
	text = joinQuotedLiterals(text)
	text = behaviorTokenSeparators.Replace(text)
	text = strings.Join(strings.Fields(text), " ")
	if text == "" {
		return ""
	}
	return " " + text + " "
}

// joinQuotedLiterals removes string-literal quotes and concatenates quoted
// segments that are joined by '+'. A quoted segment is consumed together with
// its delimiters; if the following non-space character is '+' and the next
// non-space character starts another quoted segment, both segments are emitted
// contiguously. Non-quoted '+' operators are left in place for the token
// separator pass. Content of an outer literal is normalized recursively, so
// PowerShell code nested inside a command-line argument ("...'ie'+'x'...") is
// resolved as well.
func joinQuotedLiterals(text string) string {
	var out strings.Builder
	out.Grow(len(text))
	for index := 0; index < len(text); {
		if text[index] != '\'' && text[index] != '"' {
			out.WriteByte(text[index])
			index++
			continue
		}
		content, next, ok := readQuotedLiteral(text, index)
		if !ok {
			// Unterminated literal: drop the stray delimiter and keep scanning.
			index++
			continue
		}
		out.WriteString(normalizeQuotedContent(content))
		index = next
		for {
			probe := index
			for probe < len(text) && (text[probe] == ' ' || text[probe] == '\t') {
				probe++
			}
			if probe >= len(text) || text[probe] != '+' {
				break
			}
			probe++
			for probe < len(text) && (text[probe] == ' ' || text[probe] == '\t') {
				probe++
			}
			if probe >= len(text) || (text[probe] != '\'' && text[probe] != '"') {
				break
			}
			content, next, ok = readQuotedLiteral(text, probe)
			if !ok {
				break
			}
			out.WriteString(normalizeQuotedContent(content))
			index = next
		}
	}
	return out.String()
}

// normalizeQuotedContent resolves quoting and concatenation inside the content
// of a quoted segment. Plain content is returned unchanged.
func normalizeQuotedContent(content string) string {
	if !strings.ContainsAny(content, `'"`) {
		return content
	}
	return joinQuotedLiterals(content)
}

// readQuotedLiteral reads one single- or double-quoted segment starting at
// start. A doubled delimiter inside the literal is treated as an escaped
// literal character, matching PowerShell's quoting rules.
func readQuotedLiteral(text string, start int) (string, int, bool) {
	quote := text[start]
	var out strings.Builder
	for index := start + 1; index < len(text); index++ {
		if text[index] != quote {
			out.WriteByte(text[index])
			continue
		}
		if index+1 < len(text) && text[index+1] == quote {
			out.WriteByte(quote)
			index++
			continue
		}
		return out.String(), index + 1, true
	}
	return "", 0, false
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
	// An encoded-command block is direct execution evidence rather than a
	// contextual annotation: the attempt to run a hidden payload itself
	// justifies host response, even when the payload is malformed or carries
	// no recognizable content signals. All other block classes still need a
	// critical signal or two independent signal categories.
	for _, signal := range signals {
		if signal == encodedCommandSignal {
			return true
		}
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
		if strings.Contains(signal, "amsi") || strings.Contains(signal, "writeprocessmemory") || strings.Contains(signal, "createremotethread") || strings.Contains(signal, "minidump") || strings.Contains(signal, "sekurlsa") || strings.Contains(signal, "renamed-lolbin") {
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
