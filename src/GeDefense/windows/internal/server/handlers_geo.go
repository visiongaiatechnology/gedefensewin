package server

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/visiongaiatechnology/gedefense/windows/internal/geoip"
)

type mapSource struct {
	IP          string   `json:"ip"`
	CountryCode string   `json:"country_code,omitempty"`
	Country     string   `json:"country,omitempty"`
	Latitude    *float64 `json:"latitude,omitempty"`
	Longitude   *float64 `json:"longitude,omitempty"`
	ASN         string   `json:"asn,omitempty"`
	ASName      string   `json:"as_name,omitempty"`
	State       string   `json:"state"`
	Blocked     bool     `json:"blocked"`
	Hits        int      `json:"hits"`
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
	if !status.Loaded {
		s.writeJSON(w, http.StatusOK, result)
		return
	}
	// Only genuinely observed Kinetic/WFP events and Threat-IP findings.
	// Country/ASN are context, not proof of attacker location, intent or identity.
	events := s.mhx.Status().KineticIncidents
	findings := s.mhx.NetworkFindings(150)
	hits := make(map[string]*mapSource)
	add := func(ip, state string, verified bool) {
		if net.ParseIP(ip) == nil {
			return
		}
		existing := hits[ip]
		if existing != nil {
			existing.Hits++
			if verified {
				existing.Blocked = true
				existing.State = "VERIFIED_WFP_BLOCK"
			}
			return
		}
		if len(hits) >= 150 {
			return
		}
		geo, ok := s.geo.Lookup(net.ParseIP(ip))
		row := &mapSource{IP: ip, State: state, Blocked: verified, Hits: 1}
		if ok {
			row.CountryCode = geo.CountryCode
			row.Country = geo.Country
			row.ASN = geo.ASN
			row.ASName = geo.ASName
			lat, lon := geo.Latitude, geo.Longitude
			row.Latitude = &lat
			row.Longitude = &lon
		} else {
			result.Unknown++
		}
		hits[ip] = row
	}
	for _, item := range events {
		add(item.RemoteIP, item.Classification, item.VerifiedWFPBlock)
	}
	for _, finding := range findings {
		add(finding.RemoteIP, "THREAT_INTELLIGENCE_MATCH", false)
	}
	ips := make([]string, 0, len(hits))
	for ip := range hits {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	countryTotals := make(map[string]*mapCountry)
	for _, ip := range ips {
		row := hits[ip]
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
		total.Hits += row.Hits
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
