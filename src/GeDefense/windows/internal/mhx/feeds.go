// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

const (
	feedInterval = 12 * time.Hour
	maxFeedBytes = 4 << 20
)

type feedSource struct{ Name, URL, Format string }

var feedSources = []feedSource{
	{Name: "abuse.ch Feodo Tracker", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", Format: "plain"},
	{Name: "Spamhaus DROP IPv4", URL: "https://www.spamhaus.org/drop/drop_v4.json", Format: "ndjson"},
	{Name: "Spamhaus DROP IPv6", URL: "https://www.spamhaus.org/drop/drop_v6.json", Format: "ndjson"},
}

type feedSnapshot struct {
	GeneratedUTC time.Time         `json:"generatedUtc"`
	Sources      []FeedAttribution `json:"sources"`
	Indicators   []string          `json:"indicators"`
}

type FeedAttribution struct {
	Name                string `json:"name"`
	URL                 string `json:"url"`
	Copyright           string `json:"copyright"`
	Terms               string `json:"terms,omitempty"`
	SourceTimestampUnix int64  `json:"sourceTimestampUnix,omitempty"`
}

type FeedManager struct {
	root     string
	client   *http.Client
	mu       sync.RWMutex
	status   FeedStatus
	prefixes []netip.Prefix
}

func NewFeedManager(root string) (*FeedManager, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("threat intelligence root must be absolute")
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}
	manager := &FeedManager{root: root, client: &http.Client{Transport: transport, Timeout: 45 * time.Second}, status: FeedStatus{State: "INITIALIZING"}}
	_ = manager.load()
	return manager, nil
}

func (m *FeedManager) Run(stop <-chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	_ = m.Sync(ctx)
	cancel()
	timer := time.NewTimer(feedInterval)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			_ = m.Sync(ctx)
			cancel()
			timer.Reset(feedInterval)
		}
	}
}

func (m *FeedManager) Sync(ctx context.Context) error {
	attempt := time.Now().UTC()
	all := make(map[netip.Prefix]struct{}, 2048)
	sources := make([]FeedAttribution, 0, len(feedSources))
	for _, source := range feedSources {
		prefixes, attribution, err := m.fetch(ctx, source)
		if err != nil {
			m.fail(attempt, err)
			return err
		}
		if len(prefixes) == 0 {
			err = fmt.Errorf("threat feed %s returned no valid indicators", source.Name)
			m.fail(attempt, err)
			return err
		}
		for _, prefix := range prefixes {
			all[prefix.Masked()] = struct{}{}
		}
		sources = append(sources, attribution)
	}
	indicators := make([]string, 0, len(all))
	prefixes := make([]netip.Prefix, 0, len(all))
	for prefix := range all {
		indicators = append(indicators, prefix.String())
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(indicators)
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
	snapshot := feedSnapshot{GeneratedUTC: attempt, Sources: sources, Indicators: indicators}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		m.fail(attempt, err)
		return err
	}
	digest := sha256.Sum256(payload)
	if err := atomicWrite(filepath.Join(m.root, "threat-intelligence.json"), append(payload, '\n')); err != nil {
		m.fail(attempt, err)
		return err
	}
	m.mu.Lock()
	m.prefixes = prefixes
	m.status = FeedStatus{LastAttemptUTC: attempt, LastSuccessUTC: attempt, NextSyncUTC: attempt.Add(feedInterval), Indicators: len(prefixes), Generation: hex.EncodeToString(digest[:]), State: "CURRENT"}
	m.mu.Unlock()
	return nil
}

func (m *FeedManager) fetch(ctx context.Context, source feedSource) ([]netip.Prefix, FeedAttribution, error) {
	attribution := FeedAttribution{Name: source.Name, URL: source.URL}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return nil, attribution, err
	}
	req.Header.Set("Accept", "application/json, text/json, text/plain")
	req.Header.Set("User-Agent", "VGT-GeDefense-MHX/6.0")
	response, err := m.client.Do(req)
	if err != nil {
		return nil, attribution, fmt.Errorf("fetch %s: %w", source.Name, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, attribution, fmt.Errorf("fetch %s: HTTP %d", source.Name, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxFeedBytes+1))
	if err != nil {
		return nil, attribution, fmt.Errorf("read %s: %w", source.Name, err)
	}
	if len(body) == 0 || len(body) > maxFeedBytes {
		return nil, attribution, fmt.Errorf("feed %s violated size boundary", source.Name)
	}
	if source.Format == "plain" {
		prefixes, parseErr := parsePlainFeed(body)
		attribution.Copyright = "CC0 abuse.ch Feodo Tracker"
		return prefixes, attribution, parseErr
	}
	prefixes, parseErr := parseNDJSONFeed(body)
	if parseErr == nil {
		attribution, parseErr = parseNDJSONAttribution(body, attribution)
	}
	return prefixes, attribution, parseErr
}

func parsePlainFeed(body []byte) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, 128)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if address, err := netip.ParseAddr(line); err == nil {
			result = append(result, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	return result, scanner.Err()
}

func parseNDJSONFeed(body []byte) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, 1024)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var record struct {
			CIDR string `json:"cidr"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, errors.New("threat feed JSON validation failed")
		}
		if record.CIDR == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(record.CIDR)
		if err != nil {
			return nil, errors.New("threat feed CIDR validation failed")
		}
		result = append(result, prefix.Masked())
	}
	return result, scanner.Err()
}

func parseNDJSONAttribution(body []byte, attribution FeedAttribution) (FeedAttribution, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	found := false
	for scanner.Scan() {
		var record struct {
			Type      string `json:"type"`
			Timestamp int64  `json:"timestamp"`
			Copyright string `json:"copyright"`
			Terms     string `json:"terms"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return attribution, errors.New("threat feed attribution validation failed")
		}
		if record.Type != "metadata" {
			continue
		}
		copyright := strings.TrimSpace(record.Copyright)
		terms := strings.TrimSpace(record.Terms)
		if record.Timestamp <= 0 || copyright == "" || terms == "" {
			return attribution, errors.New("threat feed attribution is incomplete")
		}
		attribution.SourceTimestampUnix = record.Timestamp
		attribution.Copyright = copyright
		attribution.Terms = terms
		found = true
	}
	if err := scanner.Err(); err != nil {
		return attribution, err
	}
	if !found {
		return attribution, errors.New("threat feed attribution is missing")
	}
	return attribution, nil
}

func (m *FeedManager) Contains(address netip.Addr) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, prefix := range m.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (m *FeedManager) Status() FeedStatus { m.mu.RLock(); defer m.mu.RUnlock(); return m.status }

func (m *FeedManager) SnapshotPath() string { return filepath.Join(m.root, "threat-intelligence.json") }

func (m *FeedManager) fail(attempt time.Time, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.LastAttemptUTC = attempt
	m.status.NextSyncUTC = attempt.Add(feedInterval)
	m.status.State = "STALE"
	m.status.Error = err.Error()
}

func (m *FeedManager) load() error {
	payload, err := os.ReadFile(filepath.Join(m.root, "threat-intelligence.json"))
	if err != nil {
		return err
	}
	var snapshot feedSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return err
	}
	prefixes := make([]netip.Prefix, 0, len(snapshot.Indicators))
	for _, value := range snapshot.Indicators {
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil {
			return parseErr
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	digest := sha256.Sum256(bytesTrimSpace(payload))
	m.mu.Lock()
	m.prefixes = prefixes
	m.status = FeedStatus{LastSuccessUTC: snapshot.GeneratedUTC, NextSyncUTC: snapshot.GeneratedUTC.Add(feedInterval), Indicators: len(prefixes), Generation: hex.EncodeToString(digest[:]), State: "CACHED"}
	m.mu.Unlock()
	return nil
}

func atomicWrite(path string, payload []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".mhx-feed-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(payload)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func bytesTrimSpace(value []byte) []byte { return []byte(strings.TrimSpace(string(value))) }
