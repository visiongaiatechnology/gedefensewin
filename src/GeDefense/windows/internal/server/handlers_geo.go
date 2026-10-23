package server

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/geoip"
)

type mapSource struct {
	IP                     string    `json:"ip"`
	CountryCode            string    `json:"country_code,omitempty"`
	Country                string    `json:"country,omitempty"`
	Latitude               *float64  `json:"latitude,omitempty"`
	Longitude              *float64  `json:"longitude,omitempty"`
	ASN                    string    `json:"asn,omitempty"`
	ASName                 string    `json:"as_name,omitempty"`
	State                  string    `json:"state"`
	Blocked                bool      `json:"blocked"`
	Hits                   uint64    `json:"hits"`
	Area                   string    `json:"area"`
	Areas                  []string  `json:"areas"`
	LastSeen               time.Time `json:"last_seen"`
	LocalPort              uint16    `json:"local_port"`
	Summary                string    `json:"summary"`
	Severity               string    `json:"severity"`
	Rules                  []string  `json:"rules"`
	Process                string    `json:"process"`
	CorrelationID          string    `json:"correlation_id,omitempty"`
	Direction              string    `json:"direction"`
	VerifiedGeDefenseBlock bool      `json:"verified_gedefense_block"`
}
type mapCountry struct {
	Code    string `json:"code"`
	Name    string `json:"name"`
	Hits    int    `json:"hits"`
	Blocked int    `json:"blocked"`
}

// geoPath accepts a local operator configured path or a file next to the executable.
// Never download data or send source IP addresses to geolocation services.
func geoPath() string {
	if path := strings.TrimSpace(os.Getenv("GEDEFENSE_GEOIP_CSV")); path != "" {
		return path
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "geoip.csv")
	}
	return ""
}
func (s *Server) initGeo() {
	s.geoOnce.Do(func() { s.geo = geoip.NewGeoResolver(geoPath()) })
}
func (s *Server) kineticGeo(w http.ResponseWriter, _ *http.Request) {
	s.initGeo()
	status := s.geo.Status()
	result := struct {
		Database  geoip.GeoStatus `json:"database"`
		Sources   []mapSource     `json:"sources"`
		Countries []mapCountry    `json:"countries"`
		Unknown   int             `json:"unknown"`
	}{Database: status, Sources: make([]mapSource, 0, 96), Countries: make([]mapCountry, 0, 64)}
	rows := s.collectMapSources(s.mhx.Status(), 150)
	countryTotals := make(map[string]*mapCountry)
	for _, item := range rows {
		row := &item
		if row.Latitude == nil {
			result.Unknown++
		}
		if len(result.Sources) < 96 {
			result.Sources = append(result.Sources, *row)
		}
		if row.CountryCode == "" {
			continue
		}
		total := countryTotals[row.CountryCode]
		if total == nil {
			total = &mapCountry{Code: row.CountryCode, Name: row.Country}
			countryTotals[row.CountryCode] = total
		}
		total.Hits += int(row.Hits)
		if row.Blocked {
			total.Blocked++
		}
	}
	for _, row := range countryTotals {
		result.Countries = append(result.Countries, *row)
	}
	sort.Slice(result.Countries, func(i, j int) bool { return result.Countries[i].Hits > result.Countries[j].Hits })
	if len(result.Countries) > 64 {
		result.Countries = result.Countries[:64]
	}
	s.writeJSON(w, http.StatusOK, result)
}
