// STATUS: PLATIN
package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/geoip"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
)

// Only recorded Windows blocks count as blocks. A blocking feed policy alone is not a witnessed block.
func witnessedBlock(response string) bool {
	switch response {
	case "WFP_BLOCK_OBSERVED", "GEDEFENSE_WFP_BLOCK", "PROTECTED_NETWORK_WFP_BLOCK_OBSERVED",
		"GEDEFENSE_STALE_PROTECTED_NETWORK_BLOCK", "NETWORK_BLOCKED", "GEDEFENSE_NETWORK_BLOCKED",
		"PROTECTED_NETWORK_BLOCK_OBSERVED", "NETWORK_BLOCKED_HOST_RESPONSE_AUTHORITY_PRESENT":
		return true
	}
	return false
}

// collectMapSources is shared by Kinetic and the overview, including when the local CSV is unavailable.
func (s *Server) collectMapSources(status mhx.Status, limit int) []mapSource {
	if limit < 1 || limit > 500 {
		limit = 250
	}
	byIP := make(map[string]*mapSource, limit)
	add := func(candidate mapSource) {
		ip := net.ParseIP(candidate.IP)
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
			return
		}
		candidate.IP = ip.String()
		if existing := byIP[candidate.IP]; existing != nil {
			existing.Blocked = existing.Blocked || candidate.Blocked
			existing.VerifiedGeDefenseBlock = existing.VerifiedGeDefenseBlock || candidate.VerifiedGeDefenseBlock
			if candidate.Hits > existing.Hits {
				existing.Hits = candidate.Hits
			}
			for _, area := range candidate.Areas {
				found := false
				for _, previous := range existing.Areas {
					if previous == area {
						found = true
						break
					}
				}
				if !found {
					existing.Areas = append(existing.Areas, area)
				}
			}
			if candidate.LastSeen.After(existing.LastSeen) {
				existing.LastSeen, existing.LocalPort = candidate.LastSeen, candidate.LocalPort
			}
			if candidate.CorrelationID != "" {
				existing.CorrelationID = candidate.CorrelationID
				existing.Summary, existing.State = candidate.Summary, candidate.State
			}
			if candidate.Process != "" {
				existing.Process = candidate.Process
			}
			if candidate.Area == "ti" || candidate.Area == "xdr" {
				existing.Rules, existing.Severity = candidate.Rules, candidate.Severity
				if existing.CorrelationID == "" {
					existing.Summary = candidate.Summary
				}
			}
			return
		}
		if len(byIP) < 1024 {
			copied := candidate
			byIP[candidate.IP] = &copied
		}
	}
	for _, source := range status.KineticSources {
		detail := fmt.Sprintf("%d eingehende Windows-WFP-Sperrereignisse", source.Hits)
		if source.PortlessBlocks > 0 {
			detail += fmt.Sprintf(" · %d ohne Transportport", source.PortlessBlocks)
		}
		add(mapSource{IP: source.IP, Hits: source.Hits, Area: "kinetic", Areas: []string{"kinetic"},
			State: "WFP_BLOCK_OBSERVED", Blocked: true, LastSeen: source.LastSeen, LocalPort: source.LastPort,
			Summary: detail, Severity: "info", Direction: "inbound"})
	}
	for _, incident := range status.KineticIncidents {
		add(mapSource{IP: incident.RemoteIP, Hits: 1, Area: "kinetic", Areas: []string{"kinetic"},
			State: incident.Classification, Blocked: true, VerifiedGeDefenseBlock: incident.VerifiedWFPBlock,
			LastSeen: incident.TimestampUTC, LocalPort: incident.LocalPort, Summary: incident.Classification,
			Severity: "medium", Rules: incident.ThreatSources, Direction: "inbound"})
	}
	for _, finding := range s.mhx.NetworkFindings(250) {
		add(mapSource{IP: finding.RemoteIP, Hits: 1, Area: "ti", Areas: []string{"ti"},
			State: finding.Response, Blocked: witnessedBlock(finding.Response), LastSeen: finding.TimestampUTC,
			LocalPort: finding.LocalPort, Process: finding.Image, CorrelationID: finding.CorrelationID,
			Summary:  "Threat-IP: " + strings.Join(finding.ThreatSources, ", "),
			Severity: string(finding.Severity), Rules: finding.ThreatSources, Direction: "unknown"})
	}
	for _, story := range s.mhx.AttackStories(120) {
		add(mapSource{IP: story.RemoteIP, Hits: 1, Area: "xdr", Areas: []string{"xdr"},
			State: story.Response, Blocked: witnessedBlock(story.Response), LastSeen: story.UpdatedUTC,
			Process: story.Image, CorrelationID: story.ProcessAnalysisID, Summary: "Prozess-/Netzwerkkorrelation: " + strings.Join(story.Signals, ", "),
			Severity: string(story.Severity), Rules: story.Signals, Direction: "unknown"})
	}
	rows := make([]mapSource, 0, len(byIP))
	for _, item := range byIP {
		ip := net.ParseIP(item.IP)
		if geo, ok := s.geo.Lookup(ip); ok {
			item.CountryCode, item.Country, item.ASN, item.ASName = geo.CountryCode, geo.Country, geo.ASN, geo.ASName
			if geo.Latitude != 0 || geo.Longitude != 0 {
				lat, lon := geo.Latitude, geo.Longitude
				item.Latitude, item.Longitude = &lat, &lon
			}
		} else if special, ok := geoip.ClassifySpecial(ip); ok {
			item.CountryCode, item.Country, item.ASN, item.ASName = special.CountryCode, special.Country, special.ASN, special.ASName
		}
		rows = append(rows, *item)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].LastSeen.Equal(rows[j].LastSeen) {
			return rows[i].IP < rows[j].IP
		}
		return rows[i].LastSeen.After(rows[j].LastSeen)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

type mapOrigin struct {
	Known       bool    `json:"known"`
	IP          string  `json:"ip,omitempty"`
	InternalIP  string  `json:"internal_ip,omitempty"`
	ExternalIP  string  `json:"external_ip,omitempty"`
	Latitude    float64 `json:"lat"`
	Longitude   float64 `json:"lon"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	ASName      string  `json:"as_name,omitempty"`
	Source      string  `json:"source,omitempty"`
	Reason      string  `json:"reason,omitempty"`
}

// localOutboundIP resolves the local address of the interface the default route
// would use. A connected UDP socket transmits no packet (the kernel only
// performs a local route lookup), so this stays inside the zero-egress policy;
// the fallback enumerates local interface addresses.
func localOutboundIP() net.IP {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 80})
	if err == nil {
		defer conn.Close()
		if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && udpAddr != nil && udpAddr.IP != nil {
			return udpAddr.IP
		}
	}
	if addresses, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addresses {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil && ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && ip.To4() != nil {
				return ip
			}
		}
	}
	return nil
}

// publicIPSource names the local, already available origin of the host address.
type publicIPSource int

const (
	// publicIPSourceUnavailable means no local/configured source provided an
	// address. The UI renders that honestly instead of guessing.
	publicIPSourceUnavailable publicIPSource = iota
	// publicIPSourceOperator means the operator explicitly configured the value.
	publicIPSourceOperator
	// publicIPSourceInterface means a public unicast address of a local network
	// interface was used.
	publicIPSourceInterface
)

// label is the stable JSON/UI label for the source. There is deliberately no
// external/DNS label: GeDefense runs zero-egress.
func (source publicIPSource) label() string {
	switch source {
	case publicIPSourceOperator:
		return "operator-configured"
	case publicIPSourceInterface:
		return "public-interface"
	default:
		return ""
	}
}

// publicIPResult is the outcome of the local public-IP lookup.
type publicIPResult struct {
	IP     string
	Source publicIPSource
}

// operatorPublicIPEnv is the only configuration source for the host's public
// address. It is read locally and never validated against a network service.
const operatorPublicIPEnv = "GEDEFENSE_MAP_HOST_IP"

// publicIPResolver answers "what is this host's public address?" exclusively
// from local state. GeDefense documents a zero-egress policy: neither plaintext
// UDP-DNS (the removed FIND-WIN-023 behaviour) nor any HTTP client may be used
// to discover the address, and a request must never block on a network timeout.
// Therefore this type owns no network client at all.
type publicIPResolver struct {
	lookupEnv      func(string) string
	interfaceAddrs func() ([]net.Addr, error)
	// externalLookup is the removed external discovery seam. It is nil for every
	// production resolver and discover never calls it: the field exists so the
	// regression test can wire a function that fails the test, which proves that
	// a reintroduced external lookup cannot slip through unnoticed.
	externalLookup func(context.Context, string) ([]string, error)
}

// defaultPublicIPResolver is the production resolver: environment plus local
// interface enumeration, nothing else.
var defaultPublicIPResolver = publicIPResolver{
	lookupEnv:      os.Getenv,
	interfaceAddrs: net.InterfaceAddrs,
}

// discover reports the host's public address from operator configuration or a
// local interface. Without such a source it reports unavailable (empty result);
// it never performs an external lookup and never sleeps on a timeout.
func (resolver publicIPResolver) discover() publicIPResult {
	if resolver.lookupEnv != nil {
		if configured := strings.TrimSpace(resolver.lookupEnv(operatorPublicIPEnv)); configured != "" {
			if ip := net.ParseIP(configured); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				return publicIPResult{IP: ip.String(), Source: publicIPSourceOperator}
			}
		}
	}
	if resolver.interfaceAddrs != nil {
		if addresses, err := resolver.interfaceAddrs(); err == nil {
			for _, address := range addresses {
				ip, _, err := net.ParseCIDR(address.String())
				if err != nil || ip == nil || ip.IsLoopback() || ip.IsUnspecified() || !ip.IsGlobalUnicast() {
					continue
				}
				// Private, carrier-grade and link-local ranges are not a public
				// address; they are reported separately as the local interface.
				if _, isSpecial := geoip.ClassifySpecial(ip); isSpecial {
					continue
				}
				return publicIPResult{IP: ip.String(), Source: publicIPSourceInterface}
			}
		}
	}
	// Zero-Egress: no external discovery. resolver.externalLookup stays unused.
	return publicIPResult{}
}

// publicIPStatusReason is the honest operator-facing reason for an unavailable
// public address, rendered by the overview map.
const publicIPStatusReason = "Keine öffentliche IP aus lokaler Konfiguration oder Schnittstelle verfügbar (Zero-Egress: keine externe Abfrage)."

func (s *Server) mapOrigin() mapOrigin {
	localIP := localOutboundIP()
	internalIPStr := ""
	if localIP != nil {
		internalIPStr = localIP.String()
	}

	// The public address is never discovered through the network; it comes from
	// operator configuration or a public interface address that already exists.
	resolved := defaultPublicIPResolver.discover()
	externalIPStr := resolved.IP

	origin := mapOrigin{
		InternalIP: internalIPStr,
		ExternalIP: externalIPStr,
	}

	targetIPStr := externalIPStr
	sourceLabel := resolved.Source.label()
	if targetIPStr == "" {
		targetIPStr = internalIPStr
		sourceLabel = "local-interface"
	}

	if targetIPStr == "" {
		origin.Reason = publicIPStatusReason
		return origin
	}

	origin.IP = targetIPStr
	origin.Source = sourceLabel

	ip := net.ParseIP(targetIPStr)
	if ip == nil {
		origin.Reason = "Ungültige IP-Adresse"
		return origin
	}

	if geo, ok := s.geo.Lookup(ip); ok {
		origin.Known = true
		origin.Latitude = geo.Latitude
		origin.Longitude = geo.Longitude
		origin.Country = geo.Country
		origin.CountryCode = geo.CountryCode
		origin.ASN = geo.ASN
		origin.ASName = geo.ASName
		return origin
	}

	if special, isSpecial := geoip.ClassifySpecial(ip); isSpecial {
		origin.Country = special.Country
		origin.CountryCode = special.CountryCode
		origin.ASN = special.ASN
		origin.ASName = special.ASName
		origin.Reason = "Host im lokalen Netzwerk (" + special.ASName + "); externer Standort nicht aufgelöst."
		return origin
	}

	origin.Reason = "Standort des Hosts nicht in lokaler GeoIP-Datenbank vorhanden"
	return origin
}

func (s *Server) overviewThreatMap(w http.ResponseWriter, r *http.Request) {
	limit, err := parseBoundedInteger(r.URL.Query().Get("limit"), 250, 1, 500)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid source window")
		return
	}
	eventLimit, err := parseBoundedInteger(r.URL.Query().Get("events"), 120, 1, 300)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid event window")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	s.initGeo()
	var sources []mapSource
	var recent []mapEvent
	totals := map[string]int{"sources": 0, "placed": 0, "blocked": 0, "countries": 0, "kinetic": 0, "ti": 0, "xdr": 0, "host": 0}
	if mode == "programs" {
		sources, recent = s.collectProgramMapSources(limit, eventLimit)
	} else {
		status := s.mhx.Status()
		sources = s.collectMapSources(status, limit)
		recent = make([]mapEvent, 0, eventLimit)
	}
	totals["sources"] = len(sources)
	countries := make(map[string]bool)
	for _, source := range sources {
		if source.Latitude != nil && source.Longitude != nil {
			totals["placed"]++
		}
		if source.Blocked {
			totals["blocked"]++
		}
		if source.CountryCode != "" {
			countries[source.CountryCode] = true
		}
		for _, area := range source.Areas {
			totals[area]++
		}
		if mode != "programs" && len(recent) < eventLimit {
			recent = append(recent, mapEvent{ID: source.IP + ":" + source.LastSeen.Format(time.RFC3339Nano), Time: source.LastSeen,
				Remote: source.IP, Area: source.Area, Country: source.Country, CountryCode: source.CountryCode,
				Blocked: source.Blocked, Severity: source.Severity, Decision: source.State, Summary: source.Summary,
				Process: source.Process, Rules: source.Rules, Path: portDescription(source.LocalPort)})
		}
	}
	totals["countries"] = len(countries)
	geo := s.geo.Status()
	s.writeJSON(w, http.StatusOK, struct {
		Sources   []mapSource    `json:"sources"`
		Recent    []mapEvent     `json:"recent"`
		Origin    mapOrigin      `json:"origin"`
		Geo       mapGeoStatus   `json:"geo"`
		Totals    map[string]int `json:"totals"`
		Generated time.Time      `json:"generated"`
	}{sources, recent, s.mapOrigin(), mapGeoStatus{geo.Loaded, geo.Entries}, totals, time.Now().UTC()})
}

func (s *Server) collectProgramMapSources(limit, eventLimit int) ([]mapSource, []mapEvent) {
	ctrl, ok := s.mhx.(styxControlProvider)
	if !ok {
		return []mapSource{}, []mapEvent{}
	}
	blockedSet := make(map[string]bool)
	for _, cidr := range ctrl.StyxBlockedTargets() {
		blockedSet[strings.TrimSuffix(cidr, "/32")] = true
	}
	progs := ctrl.StyxProgramTraffic()
	byIP := make(map[string]*mapSource, limit)
	recent := make([]mapEvent, 0, eventLimit)
	for _, prog := range progs {
		for _, dest := range prog.Destinations {
			ip := net.ParseIP(dest.IP)
			if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
				continue
			}
			ipStr := ip.String()
			isBlocked := blockedSet[ipStr]
			state := "OUTBOUND_FLOW"
			sev := "info"
			if isBlocked {
				state = "WFP_BLOCK_OBSERVED"
				sev = "high"
			}
			var cc, country, asn, asName string
			var latPtr, lonPtr *float64
			if geo, found := s.geo.Lookup(ip); found {
				cc, country, asn, asName = geo.CountryCode, geo.Country, geo.ASN, geo.ASName
				if geo.Latitude != 0 || geo.Longitude != 0 {
					lat, lon := geo.Latitude, geo.Longitude
					latPtr, lonPtr = &lat, &lon
				}
			} else if special, isSpec := geoip.ClassifySpecial(ip); isSpec {
				cc, country, asn, asName = special.CountryCode, special.Country, special.ASN, special.ASName
			}
			summary := fmt.Sprintf("%s → %s:%d (TX %s · RX %s)", prog.Process, ipStr, dest.Port, formatByteCount(dest.TxBytes), formatByteCount(dest.RxBytes))
			if len(recent) < eventLimit {
				procPath := prog.ProcessPath
				if procPath == "" {
					procPath = fmt.Sprintf("Port %d → %d", dest.LocalPort, dest.Port)
				}
				recent = append(recent, mapEvent{
					ID:          fmt.Sprintf("%s:%s:%d", prog.Process, ipStr, dest.Port),
					Time:        dest.LastSeen,
					Remote:      ipStr,
					Area:        "host",
					Country:     country,
					CountryCode: cc,
					Blocked:     isBlocked,
					Severity:    sev,
					Decision:    state,
					Summary:     summary,
					Process:     prog.Process,
					Path:        procPath,
					Rules:       []string{fmt.Sprintf("TCP/%d", dest.Port)},
				})
			}
			if existing := byIP[ipStr]; existing != nil {
				existing.Blocked = existing.Blocked || isBlocked
				existing.Hits += uint64(maxInt(dest.Connections, 1))
				if dest.LastSeen.After(existing.LastSeen) {
					existing.LastSeen = dest.LastSeen
				}
				if prog.Process != "" && !strings.Contains(existing.Process, prog.Process) && len(existing.Process) < 180 {
					existing.Process += ", " + prog.Process
				}
				continue
			}
			if len(byIP) < limit {
				hits := uint64(dest.Connections)
				if hits == 0 {
					hits = 1
				}
				byIP[ipStr] = &mapSource{
					IP:          ipStr,
					CountryCode: cc,
					Country:     country,
					Latitude:    latPtr,
					Longitude:   lonPtr,
					ASN:         asn,
					ASName:      asName,
					State:       state,
					Blocked:     isBlocked,
					Hits:        hits,
					Area:        "host",
					Areas:       []string{"host"},
					LastSeen:    dest.LastSeen,
					LocalPort:   dest.LocalPort,
					Summary:     summary,
					Severity:    sev,
					Rules:       []string{fmt.Sprintf("TCP/%d", dest.Port)},
					Process:     prog.Process,
					Path:        prog.ProcessPath,
					Direction:   "outbound",
				}
			}
		}
	}
	rows := make([]mapSource, 0, len(byIP))
	for _, src := range byIP {
		rows = append(rows, *src)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Hits != rows[j].Hits {
			return rows[i].Hits > rows[j].Hits
		}
		return rows[i].LastSeen.After(rows[j].LastSeen)
	})
	return rows, recent
}

type programTrafficDestinationView struct {
	IP          string    `json:"ip"`
	Port        uint16    `json:"port"`
	CountryCode string    `json:"countryCode,omitempty"`
	Country     string    `json:"country,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	ASName      string    `json:"asName,omitempty"`
	TxBytes     uint64    `json:"txBytes"`
	RxBytes     uint64    `json:"rxBytes"`
	Connections int       `json:"connections"`
	Blocked     bool      `json:"blocked,omitempty"`
	LastSeen    time.Time `json:"lastSeen"`
}

type programTrafficItemView struct {
	Process      string                          `json:"process"`
	ProcessPath  string                          `json:"processPath,omitempty"`
	PIDs         []int                           `json:"pids"`
	Connections  int                             `json:"connections"`
	TxBytes      uint64                          `json:"txBytes"`
	RxBytes      uint64                          `json:"rxBytes"`
	TotalBytes   uint64                          `json:"totalBytes"`
	SharePct     float64                         `json:"sharePct"`
	Whitelisted  bool                            `json:"whitelisted,omitempty"`
	Blocked      bool                            `json:"blocked,omitempty"`
	LastSeen     time.Time                       `json:"lastSeen"`
	Destinations []programTrafficDestinationView `json:"destinations"`
}

type programTrafficCountryBreakdown struct {
	Code        string  `json:"code"`
	Name        string  `json:"name"`
	Bytes       uint64  `json:"bytes"`
	Connections int     `json:"connections"`
	Programs    int     `json:"programs"`
	SharePct    float64 `json:"sharePct"`
}

type programTrafficASNBreakdown struct {
	ASN         string  `json:"asn"`
	ASName      string  `json:"asName"`
	CountryCode string  `json:"countryCode,omitempty"`
	Bytes       uint64  `json:"bytes"`
	Connections int     `json:"connections"`
	SharePct    float64 `json:"sharePct"`
}

func (s *Server) overviewProgramTraffic(w http.ResponseWriter, r *http.Request) {
	page, err := parseBoundedInteger(r.URL.Query().Get("page"), 1, 1, 1000)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid page parameter")
		return
	}
	pageSize, err := parseBoundedInteger(r.URL.Query().Get("pageSize"), 10, 1, 50)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid pageSize parameter")
		return
	}
	s.initGeo()
	geo := s.geo.Status()

	var rawPrograms []mhx.StyxProgramTrafficSummary
	blockedSet := make(map[string]bool)
	whitelistSet := make(map[string]bool)
	if ctrl, ok := s.mhx.(styxControlProvider); ok {
		rawPrograms = ctrl.StyxProgramTraffic()
		for _, cidr := range ctrl.StyxBlockedTargets() {
			blockedSet[strings.TrimSuffix(cidr, "/32")] = true
		}
		for _, wl := range ctrl.StyxWhitelist() {
			whitelistSet[strings.ToLower(strings.TrimSpace(wl))] = true
		}
	}

	var totalTx, totalRx uint64
	totalConns := 0
	countryMap := make(map[string]*programTrafficCountryBreakdown)
	countryProgs := make(map[string]map[string]struct{})
	asnMap := make(map[string]*programTrafficASNBreakdown)

	allViews := make([]programTrafficItemView, 0, len(rawPrograms))
	for _, prog := range rawPrograms {
		totalTx += prog.TxBytes
		totalRx += prog.RxBytes
		totalConns += prog.Connections
		progKey := strings.ToLower(prog.ProcessPath + "|" + prog.Process)
		progBlocked := false
		progWhitelisted := whitelistSet[strings.ToLower(prog.ProcessPath)] || whitelistSet[strings.ToLower(prog.Process)]
		destViews := make([]programTrafficDestinationView, 0, len(prog.Destinations))
		for _, dest := range prog.Destinations {
			ip := net.ParseIP(dest.IP)
			ipStr := dest.IP
			if ip != nil {
				ipStr = ip.String()
			}
			isBlocked := blockedSet[ipStr]
			if isBlocked {
				progBlocked = true
			}
			cc, cname, asn, asName := "UN", "Nicht aufgelöst", "", ""
			if ip != nil {
				if g, ok := s.geo.Lookup(ip); ok {
					if g.CountryCode != "" {
						cc = g.CountryCode
					}
					if g.Country != "" {
						cname = g.Country
					}
					asn, asName = g.ASN, g.ASName
				} else if sp, ok := geoip.ClassifySpecial(ip); ok {
					cc, cname, asn, asName = sp.CountryCode, sp.Country, sp.ASN, sp.ASName
				}
			}
			bytes := dest.TxBytes + dest.RxBytes
			cb := countryMap[cc]
			if cb == nil {
				cb = &programTrafficCountryBreakdown{Code: cc, Name: cname}
				countryMap[cc] = cb
				countryProgs[cc] = make(map[string]struct{})
			}
			cb.Bytes += bytes
			cb.Connections += maxInt(dest.Connections, 1)
			countryProgs[cc][progKey] = struct{}{}

			if asn != "" {
				ab := asnMap[asn]
				if ab == nil {
					ab = &programTrafficASNBreakdown{ASN: asn, ASName: asName, CountryCode: cc}
					asnMap[asn] = ab
				}
				ab.Bytes += bytes
				ab.Connections += maxInt(dest.Connections, 1)
			}

			destViews = append(destViews, programTrafficDestinationView{
				IP:          ipStr,
				Port:        dest.Port,
				CountryCode: cc,
				Country:     cname,
				ASN:         asn,
				ASName:      asName,
				TxBytes:     dest.TxBytes,
				RxBytes:     dest.RxBytes,
				Connections: dest.Connections,
				Blocked:     isBlocked,
				LastSeen:    dest.LastSeen,
			})
		}
		allViews = append(allViews, programTrafficItemView{
			Process:      prog.Process,
			ProcessPath:  prog.ProcessPath,
			PIDs:         prog.PIDs,
			Connections:  prog.Connections,
			TxBytes:      prog.TxBytes,
			RxBytes:      prog.RxBytes,
			TotalBytes:   prog.TotalBytes,
			Whitelisted:  progWhitelisted,
			Blocked:      progBlocked,
			LastSeen:     prog.LastSeen,
			Destinations: destViews,
		})
	}

	grandTotalBytes := totalTx + totalRx
	for i := range allViews {
		if grandTotalBytes > 0 {
			allViews[i].SharePct = float64(allViews[i].TotalBytes) * 100 / float64(grandTotalBytes)
		} else if totalConns > 0 {
			allViews[i].SharePct = float64(allViews[i].Connections) * 100 / float64(totalConns)
		}
	}

	countryList := make([]programTrafficCountryBreakdown, 0, len(countryMap))
	var countryBytesSum uint64
	countryConnsSum := 0
	for cc, cb := range countryMap {
		cb.Programs = len(countryProgs[cc])
		countryBytesSum += cb.Bytes
		countryConnsSum += cb.Connections
	}
	for _, cb := range countryMap {
		if countryBytesSum > 0 {
			cb.SharePct = float64(cb.Bytes) * 100 / float64(countryBytesSum)
		} else if countryConnsSum > 0 {
			cb.SharePct = float64(cb.Connections) * 100 / float64(countryConnsSum)
		}
		countryList = append(countryList, *cb)
	}
	sort.Slice(countryList, func(i, j int) bool {
		if countryList[i].Bytes != countryList[j].Bytes {
			return countryList[i].Bytes > countryList[j].Bytes
		}
		if countryList[i].Connections != countryList[j].Connections {
			return countryList[i].Connections > countryList[j].Connections
		}
		return countryList[i].Code < countryList[j].Code
	})
	if len(countryList) > 10 {
		countryList = countryList[:10]
	}

	asnList := make([]programTrafficASNBreakdown, 0, len(asnMap))
	var asnBytesSum uint64
	asnConnsSum := 0
	for _, ab := range asnMap {
		asnBytesSum += ab.Bytes
		asnConnsSum += ab.Connections
	}
	for _, ab := range asnMap {
		if asnBytesSum > 0 {
			ab.SharePct = float64(ab.Bytes) * 100 / float64(asnBytesSum)
		} else if asnConnsSum > 0 {
			ab.SharePct = float64(ab.Connections) * 100 / float64(asnConnsSum)
		}
		asnList = append(asnList, *ab)
	}
	sort.Slice(asnList, func(i, j int) bool {
		if asnList[i].Bytes != asnList[j].Bytes {
			return asnList[i].Bytes > asnList[j].Bytes
		}
		if asnList[i].Connections != asnList[j].Connections {
			return asnList[i].Connections > asnList[j].Connections
		}
		return asnList[i].ASN < asnList[j].ASN
	})
	if len(asnList) > 8 {
		asnList = asnList[:8]
	}

	totalPrograms := len(allViews)
	totalPages := 1
	if totalPrograms > 0 {
		totalPages = (totalPrograms + pageSize - 1) / pageSize
	}
	if page > totalPages {
		page = totalPages
	}
	startIdx := (page - 1) * pageSize
	endIdx := startIdx + pageSize
	if startIdx > totalPrograms {
		startIdx = totalPrograms
	}
	if endIdx > totalPrograms {
		endIdx = totalPrograms
	}
	paged := allViews[startIdx:endIdx]

	s.writeJSON(w, http.StatusOK, map[string]any{
		"pagination": map[string]int{
			"page":          page,
			"pageSize":      pageSize,
			"totalPrograms": totalPrograms,
			"totalPages":    totalPages,
		},
		"totals": map[string]any{
			"programs":       totalPrograms,
			"connections":    totalConns,
			"txBytes":        totalTx,
			"rxBytes":        totalRx,
			"totalBytes":     grandTotalBytes,
			"countries":      len(countryMap),
			"asns":           len(asnMap),
			"blockedTargets": len(blockedSet),
		},
		"geo":              mapGeoStatus{geo.Loaded, geo.Entries},
		"countryBreakdown": countryList,
		"asnBreakdown":     asnList,
		"programs":         paged,
		"generated":        time.Now().UTC(),
	})
}

func formatByteCount(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func portDescription(port uint16) string {
	if port == 0 {
		return "Kein Transportport gemeldet"
	}
	return fmt.Sprintf("Lokaler Port %d", port)
}

type mapGeoStatus struct {
	Loaded  bool `json:"loaded"`
	Entries int  `json:"entries"`
}
type mapEvent struct {
	ID          string    `json:"id"`
	Time        time.Time `json:"time"`
	Remote      string    `json:"remote"`
	Area        string    `json:"area"`
	Country     string    `json:"country"`
	CountryCode string    `json:"country_code"`
	Blocked     bool      `json:"blocked"`
	Severity    string    `json:"severity"`
	Decision    string    `json:"decision"`
	Summary     string    `json:"summary"`
	Process     string    `json:"process"`
	Path        string    `json:"path"`
	Rules       []string  `json:"rules"`
}
