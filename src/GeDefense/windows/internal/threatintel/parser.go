// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
)

const (
	maximumFeedLineBytes    = 64 << 10
	maximumSourceIndicators = 500000
)

func parseSource(source Source, body []byte) ([]netip.Prefix, Attribution, error) {
	attribution := Attribution{Name: source.Name, URL: source.URL}
	var (
		prefixes []netip.Prefix
		err      error
	)
	switch source.Format {
	case FormatPlain:
		prefixes, err = parsePlain(body)
	case FormatNDJSON:
		prefixes, attribution, err = parseNDJSON(body, attribution, source.RequiresMetadata)
	default:
		return nil, attribution, errors.New("unsupported threat feed format")
	}
	if err != nil {
		return nil, attribution, err
	}
	if len(prefixes) == 0 || len(prefixes) > maximumSourceIndicators {
		return nil, attribution, errors.New("threat feed indicator boundary rejected")
	}
	return normalizePrefixes(prefixes), attribution, nil
}

func parsePlain(body []byte) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, 1024)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maximumFeedLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		token := strings.TrimSpace(fields[0])
		if !isThreatToken(token) {
			continue
		}
		prefix, err := parseThreatToken(token)
		if err != nil {
			continue
		}
		result = append(result, prefix)
		if len(result) > maximumSourceIndicators {
			return nil, errors.New("threat feed indicator boundary exceeded")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("threat feed line boundary rejected")
	}
	return result, nil
}

func parseNDJSON(body []byte, attribution Attribution, requireMetadata bool) ([]netip.Prefix, Attribution, error) {
	result := make([]netip.Prefix, 0, 1024)
	foundMetadata := false
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maximumFeedLineBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var record struct {
			Type      string `json:"type"`
			CIDR      string `json:"cidr"`
			IP        string `json:"ip"`
			Timestamp int64  `json:"timestamp"`
			Copyright string `json:"copyright"`
			Terms     string `json:"terms"`
		}
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, attribution, errors.New("threat feed JSON validation failed")
		}
		if record.Type == "metadata" {
			copyright := strings.TrimSpace(record.Copyright)
			terms := strings.TrimSpace(record.Terms)
			if record.Timestamp <= 0 || copyright == "" || terms == "" {
				return nil, attribution, errors.New("threat feed attribution validation failed")
			}
			attribution.SourceTimestampUnix = record.Timestamp
			attribution.Copyright = copyright
			attribution.Terms = terms
			foundMetadata = true
			continue
		}
		token := strings.TrimSpace(record.CIDR)
		if token == "" {
			token = strings.TrimSpace(record.IP)
		}
		if token == "" {
			continue
		}
		prefix, err := parseThreatToken(token)
		if err != nil {
			return nil, attribution, errors.New("threat feed CIDR validation failed")
		}
		result = append(result, prefix)
		if len(result) > maximumSourceIndicators {
			return nil, attribution, errors.New("threat feed indicator boundary exceeded")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, attribution, errors.New("threat feed JSON line boundary rejected")
	}
	if requireMetadata && !foundMetadata {
		return nil, attribution, errors.New("threat feed attribution is missing")
	}
	return result, attribution, nil
}

func normalizePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	unique := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if validThreatPrefix(prefix) {
			unique[prefix.Masked()] = struct{}{}
		}
	}
	result := make([]netip.Prefix, 0, len(unique))
	for prefix := range unique {
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}
