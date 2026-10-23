// STATUS: PLATIN
package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

type mapTestMHX struct {
	*fixedMHX
	findings []mhx.NetworkFinding
	stories  []mhx.AttackStory
}

func (m *mapTestMHX) NetworkFindings(int) []mhx.NetworkFinding { return m.findings }
func (m *mapTestMHX) AttackStories(int) []mhx.AttackStory      { return m.stories }

func newMapFixture(t *testing.T, withCSV bool) http.Handler {
	t.Helper()
	root := t.TempDir()
	csvPath := filepath.Join(root, "geoip.csv")
	if withCSV {
		contents := "network,country_code,country_name,latitude,longitude,asn,as_name\n8.8.8.0/24,US,United States,37,-97,AS15169,Test Network\n1.1.1.0/24,AU,Australia,-33,151,AS13335,Test Provider\n"
		if err := os.WriteFile(csvPath, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(contents))
		if err := os.WriteFile(csvPath+".sha256", []byte(fmt.Sprintf("%x  geoip.csv\n", digest)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GEDEFENSE_GEOIP_CSV", csvPath)
	t.Setenv("GEDEFENSE_MAP_HOST_IP", "1.1.1.1")
	ledger, err := evidence.Open(filepath.Join(root, "ledger.jsonl"), filepath.Join(root, "ledger.key"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	engine := &mapTestMHX{fixedMHX: &fixedMHX{mode: "guarded", status: mhx.Status{
		KineticSources: []kinetic.Source{{IP: "8.8.8.8", Hits: 15, PortlessBlocks: 15, LastSeen: now},
			{IP: "192.168.10.20", Hits: 3, LastPort: 443, LastSeen: now.Add(-time.Second)}},
	}}, findings: []mhx.NetworkFinding{{ID: "finding", RemoteIP: "8.8.8.8", TimestampUTC: now,
		ThreatAction: threatintel.ActionCorrelateOnly, Response: "CORRELATED_ONLY", ThreatSources: []string{"test-feed"}, Severity: mhx.SeverityHigh},
		{ID: "policy-only", RemoteIP: "1.1.1.1", TimestampUTC: now.Add(-time.Second), Response: "BLOCK_DESTINATION_OBSERVED", ThreatAction: threatintel.ActionBlock}},
		stories: []mhx.AttackStory{{RemoteIP: "8.8.8.8", UpdatedUTC: now, Image: "test-process.exe", ProcessAnalysisID: "analysis-1", Signals: []string{"process.network"}, Severity: mhx.SeverityHigh, Response: "CORRELATED_ONLY"}}}
	return New("test", "01234567890123456789012345678901", fixedEngine{}, fixedAudit{}, fixedXDR{}, engine, &fixedIntegrity{}, ledger)
}

func mapRequest(t *testing.T, handler http.Handler, path string, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17831"+path, nil)
	request.RemoteAddr = "127.0.0.1:10101"
	if authenticated {
		request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestOverviewMapUsesRealObservationsAndCorrelationContext(t *testing.T) {
	handler := newMapFixture(t, true)
	response := mapRequest(t, handler, "/api/v1/overview/threat-map", true)
	if response.Code != http.StatusOK {
		t.Fatalf("status %d: %s", response.Code, response.Body)
	}
	var result struct {
		Sources []mapSource    `json:"sources"`
		Origin  mapOrigin      `json:"origin"`
		Recent  []mapEvent     `json:"recent"`
		Totals  map[string]int `json:"totals"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Sources) != 3 || !result.Origin.Known || result.Totals["placed"] != 2 {
		t.Fatalf("wrong map: %+v", result)
	}
	byIP := map[string]mapSource{}
	for _, source := range result.Sources {
		byIP[source.IP] = source
	}
	observed := byIP["8.8.8.8"]
	if observed.Hits != 15 || !observed.Blocked || observed.VerifiedGeDefenseBlock || len(observed.Areas) != 3 || observed.ASN != "AS15169" || observed.CorrelationID != "analysis-1" || observed.Process != "test-process.exe" {
		t.Fatalf("observation/correlation lost or falsely attributed: %+v", observed)
	}
	if byIP["1.1.1.1"].Blocked {
		t.Fatal("feed policy misrepresented as a witnessed block")
	}
	if byIP["192.168.10.20"].Latitude != nil {
		t.Fatal("private source geolocated")
	}
	if byIP["192.168.10.20"].ASN != "RFC 1918" || byIP["192.168.10.20"].CountryCode != "LAN" {
		t.Fatalf("private network classification missing: %+v", byIP["192.168.10.20"])
	}
	if strings.Contains(response.Body.String(), "geoip.csv") || strings.Contains(response.Body.String(), `"last_error":`) {
		t.Fatal("internal CSV path leaked")
	}
}

func TestMapRetainsObservedSourcesWithoutCSV(t *testing.T) {
	handler := newMapFixture(t, false)
	for _, path := range []string{"/api/v1/overview/threat-map", "/api/v1/mhx/geo"} {
		response := mapRequest(t, handler, path, true)
		var result struct {
			Sources []mapSource `json:"sources"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if response.Code != 200 || len(result.Sources) != 3 {
			t.Fatalf("sources hidden by CSV failure: %s", response.Body)
		}
		for _, source := range result.Sources {
			if source.Latitude != nil || source.Longitude != nil {
				t.Fatal("coordinates invented without CSV")
			}
		}
	}
}

func TestOverviewMapAuthorizationBoundsAndAssetDelivery(t *testing.T) {
	handler := newMapFixture(t, true)
	if response := mapRequest(t, handler, "/api/v1/overview/threat-map", false); response.Code != 401 {
		t.Fatal(response.Code)
	}
	for _, query := range []string{"?limit=-1", "?limit=501", "?events=301", "?events=bad"} {
		if response := mapRequest(t, handler, "/api/v1/overview/threat-map"+query, true); response.Code != 400 {
			t.Fatal(query, response.Code)
		}
	}
	for _, name := range []string{"overview-map.js", "overview-map-renderer.js", "overview-map-data.js", "overview-map-strings.js", "overview-map.css"} {
		response := mapRequest(t, handler, "/assets/"+name, false)
		if response.Code != 200 || response.Body.Len() < 100 {
			t.Fatal("module not embedded/served", name, response.Code)
		}
	}
}
