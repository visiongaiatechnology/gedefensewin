// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const maxEncodedCommandBytes = 1 << 20

// encodedCommandParameter is the full Windows PowerShell 5.1 parameter name.
// powershell.exe also accepts every unambiguous prefix of it plus the special
// short alias "ec" (verified dynamically against powershell.exe 5.1: -e, -en,
// -ec, -encodedc, -encodedco, ... and /e, /en, /ec, /encodedc all execute the
// encoded payload, while -ecc, -ecx, -ee and -encodedcommandx are rejected).
const encodedCommandParameter = "encodedcommand"
const encodedCommandShortAlias = "ec"

// encodedCommandArgument is the parsed form of one raw command-line token.
// PowerShell's parameter binder (about_Parameters) accepts a parameter value
// either as the next argument or attached to the switch with a ':' or '='
// separator, so "-EncodedCommand:<value>" and "-EncodedCommand=<value>" are
// both one token while the value itself is separated from the switch name.
type encodedCommandArgument struct {
	switchPart     string
	inlineValue    string
	hasInlineValue bool
}

// parseEncodedCommandArgument splits a switch token at its first ':' or '='
// separator. Only tokens with the PowerShell switch prefixes '-' and '/' are
// split; everything else is returned unchanged. The value of an attached
// parameter may contain further ':' or '=' characters (base64 padding, for
// example), so only the first separator is significant.
func parseEncodedCommandArgument(argument string) encodedCommandArgument {
	if len(argument) < 2 {
		return encodedCommandArgument{switchPart: argument}
	}
	switch argument[0] {
	case '-', '/':
	default:
		return encodedCommandArgument{switchPart: argument}
	}
	for index := 1; index < len(argument); index++ {
		if argument[index] != ':' && argument[index] != '=' {
			continue
		}
		return encodedCommandArgument{switchPart: argument[:index], inlineValue: argument[index+1:], hasInlineValue: true}
	}
	return encodedCommandArgument{switchPart: argument}
}

func isEncodedCommandSwitch(argument string) bool {
	parsed := parseEncodedCommandArgument(argument)
	if len(parsed.switchPart) < 2 {
		return false
	}
	switch parsed.switchPart[0] {
	case '-', '/':
	default:
		return false
	}
	candidate := strings.ToLower(parsed.switchPart[1:])
	if candidate == encodedCommandShortAlias {
		return true
	}
	if candidate == "" || len(candidate) > len(encodedCommandParameter) {
		return false
	}
	return strings.HasPrefix(encodedCommandParameter, candidate)
}

func DecodePowerShellCommand(commandLine string) (string, string, bool, error) {
	args, err := splitWindowsCommandLine(commandLine)
	if err != nil {
		return "", "", false, err
	}
	for index := 0; index < len(args); index++ {
		if !isEncodedCommandSwitch(args[index]) {
			continue
		}
		parsed := parseEncodedCommandArgument(args[index])
		value := ""
		if parsed.hasInlineValue {
			// An attached value that normalizes to nothing is a broken
			// invocation, not a request to fall back to the next argument:
			// PowerShell also fails such a command line, so fail closed.
			value = normalizeEncodedCommandValue(parsed.inlineValue)
			if value == "" {
				return "", "", true, errors.New("encoded command value is missing")
			}
		} else {
			if index+1 >= len(args) {
				return "", "", true, errors.New("encoded command value is missing")
			}
			value = strings.TrimSpace(args[index+1])
		}
		if len(value) == 0 || len(value) > maxEncodedCommandBytes*2 {
			return "", "", true, errors.New("encoded command boundary violation")
		}
		raw, decodeErr := base64.StdEncoding.Strict().DecodeString(value)
		if decodeErr != nil || len(raw) == 0 || len(raw) > maxEncodedCommandBytes {
			return "", "", true, errors.New("encoded command is not strict base64")
		}
		if bytes.HasPrefix(raw, []byte{0xff, 0xfe}) || looksUTF16LE(raw) {
			text, conversionErr := decodeUTF16LE(raw)
			return text, "UTF-16LE", true, conversionErr
		}
		if !isValidUTF8(raw) {
			return "", "", true, errors.New("encoded command character encoding is invalid")
		}
		return string(raw), "UTF-8", true, nil
	}
	return "", "", false, nil
}

// normalizeEncodedCommandValue trims an attached EncodedCommand value and
// removes one pair of surrounding single or double quotes. The command-line
// splitter already removes Windows double-quote grouping; the remaining pair
// can come from a shell string literal such as -EncodedCommand:'BASE64'.
func normalizeEncodedCommandValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		quote := value[0]
		if (quote == '"' || quote == '\'') && value[len(value)-1] == quote {
			value = strings.TrimSpace(value[1 : len(value)-1])
		}
	}
	return value
}

func looksUTF16LE(raw []byte) bool {
	if len(raw) < 4 || len(raw)%2 != 0 {
		return false
	}
	nulls := 0
	for index := 1; index < len(raw); index += 2 {
		if raw[index] == 0 {
			nulls++
		}
	}
	return nulls*100/(len(raw)/2) >= 60
}

func decodeUTF16LE(raw []byte) (string, error) {
	if len(raw)%2 != 0 {
		return "", errors.New("UTF-16LE payload has an odd byte count")
	}
	if bytes.HasPrefix(raw, []byte{0xff, 0xfe}) {
		raw = raw[2:]
	}
	units := make([]uint16, len(raw)/2)
	for index := range units {
		units[index] = uint16(raw[index*2]) | uint16(raw[index*2+1])<<8
	}
	return string(utf16.Decode(units)), nil
}

// isValidUTF8 reports whether raw is valid UTF-8. The helper is intentionally
// named apart from other package validators because a decoded payload and a
// Windows event-log string need different validation semantics.
func isValidUTF8(raw []byte) bool {
	return utf8.Valid(raw)
}

func splitWindowsCommandLine(input string) ([]string, error) {
	if strings.IndexByte(input, 0) >= 0 {
		return nil, errors.New("command line contains NUL")
	}
	args := make([]string, 0, 8)
	for index := 0; index < len(input); {
		for index < len(input) && (input[index] == ' ' || input[index] == '\t') {
			index++
		}
		if index == len(input) {
			break
		}
		var out strings.Builder
		quoted := false
		for index < len(input) {
			if input[index] == '\\' {
				start := index
				for index < len(input) && input[index] == '\\' {
					index++
				}
				count := index - start
				if index < len(input) && input[index] == '"' {
					out.WriteString(strings.Repeat("\\", count/2))
					if count%2 == 1 {
						out.WriteByte('"')
						index++
					} else {
						quoted = !quoted
						index++
					}
				} else {
					out.WriteString(strings.Repeat("\\", count))
				}
				continue
			}
			if input[index] == '"' {
				quoted = !quoted
				index++
				continue
			}
			if !quoted && (input[index] == ' ' || input[index] == '\t') {
				break
			}
			out.WriteByte(input[index])
			index++
		}
		if quoted {
			return nil, errors.New("command line has an unterminated quote")
		}
		args = append(args, out.String())
	}
	return args, nil
}
