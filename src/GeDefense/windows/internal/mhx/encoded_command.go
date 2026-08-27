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

var encodedSwitches = map[string]struct{}{
	"-encodedcommand": {}, "-enc": {}, "-enco": {}, "-encod": {}, "-encode": {}, "-encoded": {},
	"/encodedcommand": {}, "/enc": {},
}

func DecodePowerShellCommand(commandLine string) (string, string, bool, error) {
	args, err := splitWindowsCommandLine(commandLine)
	if err != nil {
		return "", "", false, err
	}
	for index := 0; index < len(args); index++ {
		key := strings.ToLower(args[index])
		if _, exists := encodedSwitches[key]; !exists {
			continue
		}
		if index+1 >= len(args) {
			return "", "", true, errors.New("encoded command value is missing")
		}
		value := strings.TrimSpace(args[index+1])
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
		if !utf8Valid(raw) {
			return "", "", true, errors.New("encoded command character encoding is invalid")
		}
		return string(raw), "UTF-8", true, nil
	}
	return "", "", false, nil
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

func utf8Valid(raw []byte) bool {
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
