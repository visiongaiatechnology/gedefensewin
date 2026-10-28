// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"strings"
	"testing"
)

// PowerShell's parameter binder accepts an attached value after ':' or '='.
// The decoder must split the raw token, treat the prefix as the switch and
// decode the remainder with the same strict base64/size validation as the
// separate-argument form.
func TestDecodeInlineEncodedCommandAcceptedForms(t *testing.T) {
	payload := `Write-Output VGT_INLINE_PROBE`
	encoded := encodedUTF16LE(payload)
	tokens := []string{
		"-EncodedCommand:" + encoded,
		"-EncodedCommand=" + encoded,
		"-encodedcommand:" + encoded,
		"-ENCODEDCOMMAND=" + encoded,
		"-e:" + encoded,
		"-e=" + encoded,
		"-en:" + encoded,
		"-en=" + encoded,
		"-enc=" + encoded,
		"-encodedc:" + encoded,
		"-ec:" + encoded,
		"-ec=" + encoded,
		"-E:" + encoded,
		"/e:" + encoded,
		"/en=" + encoded,
		"/ec:" + encoded,
		"/encodedcommand=" + encoded,
	}
	for _, token := range tokens {
		decoded, encoding, isEncoded, err := DecodePowerShellCommand("powershell.exe " + token)
		if err != nil {
			t.Fatalf("inline token %q: decode error: %v", token, err)
		}
		if !isEncoded {
			t.Fatalf("inline token %q: decoder reported encoded=false", token)
		}
		if !strings.Contains(decoded, "VGT_INLINE_PROBE") || encoding != "UTF-16LE" {
			t.Fatalf("inline token %q: decoded %q (%s)", token, decoded, encoding)
		}
	}
}

// Base64 padding contains '=' characters; only the first separator may be used
// to split the attached value, otherwise a trailing "==" would be mistaken for
// part of the switch syntax.
func TestDecodeInlineEncodedCommandKeepsBase64Padding(t *testing.T) {
	encoded := encodedUTF16LE("Get-Date") // even UTF-16LE payload => "==" padding
	if !strings.HasSuffix(encoded, "=") {
		t.Fatalf("fixture unexpectedly has no base64 padding: %q", encoded)
	}
	for _, token := range []string{"-e:" + encoded, "-e=" + encoded, "-EncodedCommand:" + encoded, "-EncodedCommand=" + encoded} {
		decoded, _, isEncoded, err := DecodePowerShellCommand("powershell.exe " + token)
		if err != nil || !isEncoded || decoded != "Get-Date" {
			t.Fatalf("inline token %q: decoded=%q encoded=%v err=%v", token, decoded, isEncoded, err)
		}
	}
}

func TestDecodeInlineEncodedCommandStripsQuotes(t *testing.T) {
	encoded := encodedUTF16LE("Get-Date")
	for _, token := range []string{
		"-e:'" + encoded + "'",
		"-EncodedCommand:'" + encoded + "'",
		"-e:\"" + encoded + "\"",
		"-EncodedCommand=\"" + encoded + "\"",
	} {
		decoded, _, isEncoded, err := DecodePowerShellCommand("powershell.exe " + token)
		if err != nil || !isEncoded || !strings.Contains(decoded, "Get-Date") {
			t.Fatalf("quoted inline token %q: decoded=%q encoded=%v err=%v", token, decoded, isEncoded, err)
		}
	}
}

func TestDecodeInlineEncodedCommandFailsClosed(t *testing.T) {
	payload := encodedUTF16LE("Get-Date")
	cases := []string{
		"powershell.exe -e:",
		"powershell.exe -e=",
		"powershell.exe -EncodedCommand:",
		"powershell.exe -EncodedCommand=",
		"powershell.exe -ec:",
		"powershell.exe -e: " + payload,
		"powershell.exe -e",
		"powershell.exe -EncodedCommand",
		"powershell.exe -e:not-base64",
		"powershell.exe -e=not base64",
		"powershell.exe -e:" + strings.Repeat("A", maxEncodedCommandBytes*2+1),
	}
	for _, commandLine := range cases {
		_, _, isEncoded, err := DecodePowerShellCommand(commandLine)
		if !isEncoded || err == nil {
			t.Fatalf("broken inline token %q failed open: encoded=%v err=%v", commandLine, isEncoded, err)
		}
	}
}

func TestDecodeInlineEncodedCommandRequiresAcceptedSwitch(t *testing.T) {
	payload := encodedUTF16LE("Get-Date")
	for _, commandLine := range []string{
		"powershell.exe -ecc:" + payload,
		"powershell.exe -ecx:" + payload,
		"powershell.exe -ee:" + payload,
		"powershell.exe -ex:" + payload,
		"powershell.exe -encodedcommandx:" + payload,
		"powershell.exe --e:" + payload,
		"powershell.exe e:" + payload,
		"powershell.exe -ExecutionPolicy:Bypass",
	} {
		_, _, isEncoded, err := DecodePowerShellCommand(commandLine)
		if isEncoded || err != nil {
			t.Fatalf("non-EncodedCommand token %q was misclassified: encoded=%v err=%v", commandLine, isEncoded, err)
		}
	}
}

func TestIsEncodedCommandSwitchRecognizesInlineForms(t *testing.T) {
	accepted := []string{
		"-e:QUJD", "-en=QUJD", "-ec:QUJD", "/e:QUJD", "/en=QUJD",
		"-EncodedCommand:QUJD", "-EncodedCommand=QUJD", "-encodedc:QUJD",
	}
	for _, argument := range accepted {
		if !isEncodedCommandSwitch(argument) {
			t.Fatalf("inline argument %q is not recognized as EncodedCommand", argument)
		}
	}
	rejected := []string{
		"-ecc:QUJD", "-ecx=QUJD", "-ee:QUJD", "-encodedcommandx:QUJD",
		"--e:QUJD", "e:QUJD", "-ExecutionPolicy:Bypass", "-NoProfile=1",
	}
	for _, argument := range rejected {
		if isEncodedCommandSwitch(argument) {
			t.Fatalf("argument %q was wrongly treated as EncodedCommand", argument)
		}
	}
}

// The separate-argument form is the historical interface and must not change.
func TestSeparateArgumentEncodedCommandRemainsSupported(t *testing.T) {
	payload := encodedUTF16LE("Get-Date")
	for _, commandLine := range []string{
		"powershell.exe -EncodedCommand " + payload,
		"powershell.exe -enc " + payload,
		"powershell.exe /encodedc " + payload,
	} {
		decoded, _, isEncoded, err := DecodePowerShellCommand(commandLine)
		if err != nil || !isEncoded || !strings.Contains(decoded, "Get-Date") {
			t.Fatalf("separate form %q regressed: decoded=%q encoded=%v err=%v", commandLine, decoded, isEncoded, err)
		}
	}
}
