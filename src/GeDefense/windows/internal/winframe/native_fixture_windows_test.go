// STATUS: PLATIN
//go:build windows

package winframe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// This serves the actual embedded UI sources with explicit test data; it never
// reaches the installed service or changes Windows security settings.
func nativeFixture(t *testing.T) *httptest.Server {
	t.Helper()
	mhx := map[string]any{"protectionMode": "guarded", "protectionHealth": "VERIFIED", "realtime": true,
		"threatIntelligence": map[string]any{"state": "CURRENT", "indicators": 123, "blockingFeedsReady": 1, "blockingFeedsTotal": 1, "enforcementGenerationSha256": "test"},
		"threatEnforcement":  map[string]any{"state": "VERIFIED", "activeGenerationSha256": "test"}, "traffic": map[string]any{},
	}
	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("../server/web"))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var payload any
		switch r.URL.Path {
		case "/":
			http.ServeFile(w, r, "../server/web/index.html")
			return
		case "/api/v1/status":
			payload = map[string]any{"version": "TEST FIXTURE", "platform": "Windows · isolated visual fixture", "mhx": mhx, "protection": map[string]bool{"Defender": true, "DefenderService": true, "RealTimeProtection": true, "Firewall": true}, "integrity": map[string]any{}}
		case "/api/v1/mhx/status":
			payload = mhx
		case "/api/v1/mhx/stories":
			payload = []any{}
		case "/api/v1/window/state":
			payload = map[string]any{"handled": false, "state": "normal"}
		case "/api/v1/health/refresh":
			checks := make([]map[string]string, 0, 7)
			for _, id := range []string{"policy", "defender", "firewall", "telemetry", "intelligence", "enforcement", "evidence"} {
				checks = append(checks, map[string]string{"id": id, "state": "healthy", "detail": "Visuelle Testdaten · keine Live-Sicherheitsmessung."})
			}
			payload = map[string]any{"healthy": true, "checkedUtc": time.Now().UTC(), "checks": checks}
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Errorf("native UI fixture response: %v", err)
		}
	})
	return httptest.NewServer(mux)
}
