package geoip

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/visiongaiatechnology/gedefense/windows/internal/cleanup"
)

const (
	maxGeoIPCSVBytes = 128 << 20
	maxGeoIPEntries  = 1_000_000
	geoCacheCapacity = 4096
)

var geoSpecialUsePrefixes = mustGeoPrefixes(
	// IPv4 special-use / non-public source space. Keep this deliberately
	// conservative: operator geography must prefer "unknown" over a false pin.
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
	// IPv6 unspecified/loopback/link-local/ULA/documentation/multicast and
	// IPv4 translation/documentation ranges that are not useful as attacker
	// geography.
	"::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001:2::/48",
	"2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
)

func mustGeoPrefixes(raw ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic("invalid built-in GeoIP exclusion prefix: " + value)
		}
		out = append(out, prefix.Masked())
	}
	return out
}

func isPublicGeoAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range geoSpecialUsePrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var (
	prefixRFC1918_10  = netip.MustParsePrefix("10.0.0.0/8")
	prefixRFC1918_172 = netip.MustParsePrefix("172.16.0.0/12")
	prefixRFC1918_192 = netip.MustParsePrefix("192.168.0.0/16")
	prefixCGNAT       = netip.MustParsePrefix("100.64.0.0/10")
	prefixLinkLocal4  = netip.MustParsePrefix("169.254.0.0/16")
	prefixLinkLocal6  = netip.MustParsePrefix("fe80::/10")
	prefixULA         = netip.MustParsePrefix("fc00::/7")
)

// ClassifySpecial classifies private, local, and special-use IP ranges.
// It returns true and a GeoRecord with descriptive network metadata (RFC and ASN name)
// with Latitude and Longitude set to 0 so they remain unplaced on the physical world map.
func ClassifySpecial(ip net.IP) (GeoRecord, bool) {
	if ip == nil {
		return GeoRecord{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return GeoRecord{}, false
	}
	return ClassifySpecialAddr(addr)
}

// ClassifySpecialAddr classifies netip.Addr for private, carrier, loopback, or link-local ranges.
func ClassifySpecialAddr(addr netip.Addr) (GeoRecord, bool) {
	if !addr.IsValid() {
		return GeoRecord{}, false
	}
	addr = addr.Unmap()
	if prefixRFC1918_192.Contains(addr) {
		return GeoRecord{CountryCode: "LAN", Country: "Lokales Netzwerk", ASN: "RFC 1918", ASName: "Lokales Heim-/Unternehmensnetz (LAN)"}, true
	}
	if prefixRFC1918_10.Contains(addr) {
		return GeoRecord{CountryCode: "LAN", Country: "Lokales Netzwerk", ASN: "RFC 1918", ASName: "Privates Unternehmensnetz (10.0.0.0/8)"}, true
	}
	if prefixRFC1918_172.Contains(addr) {
		return GeoRecord{CountryCode: "LAN", Country: "Lokales Netzwerk", ASN: "RFC 1918", ASName: "Privates Subnetz (172.16.0.0/12)"}, true
	}
	if addr.IsLoopback() {
		return GeoRecord{CountryCode: "HOST", Country: "Lokaler Host", ASN: "RFC 1122", ASName: "Loopback-Schnittstelle"}, true
	}
	if prefixLinkLocal4.Contains(addr) || prefixLinkLocal6.Contains(addr) {
		return GeoRecord{CountryCode: "LINK", Country: "Link-Local", ASN: "RFC 3927", ASName: "Link-Local / APIPA"}, true
	}
	if prefixCGNAT.Contains(addr) {
		return GeoRecord{CountryCode: "ISP", Country: "Betreibernetz (CGNAT)", ASN: "RFC 6598", ASName: "Carrier-Grade NAT (ISP)"}, true
	}
	if addr.IsMulticast() {
		return GeoRecord{CountryCode: "MCAST", Country: "Multicast", ASN: "RFC 5771", ASName: "Multicast-Netzwerk"}, true
	}
	if prefixULA.Contains(addr) {
		return GeoRecord{CountryCode: "ULA", Country: "Unique Local Address", ASN: "RFC 4193", ASName: "Privates IPv6-Subnetz (ULA)"}, true
	}
	return GeoRecord{}, false
}

// GeoRecord is intentionally coarse. GeDefense displays approximate network
// origin for operator context, not a claim about a person's physical location.
type GeoRecord struct {
	CountryCode string  `json:"country_code,omitempty"`
	Country     string  `json:"country,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	ASName      string  `json:"as_name,omitempty"`
}

type GeoStatus struct {
	Loaded           bool       `json:"loaded"`
	Path             string     `json:"path,omitempty"`
	Entries          int        `json:"entries"`
	LoadedAt         *time.Time `json:"loaded_at,omitempty"`
	SourceModifiedAt *time.Time `json:"source_modified_at,omitempty"`
	CacheEntries     int        `json:"cache_entries"`
	CacheCapacity    int        `json:"cache_capacity"`
	LastError        string     `json:"last_error,omitempty"`
}

type geoCacheEntry struct {
	Record     GeoRecord
	Found      bool
	Generation uint64
}

type GeoResolver struct {
	mu          sync.RWMutex
	v4          map[int]map[netip.Addr]GeoRecord
	v6          map[int]map[netip.Addr]GeoRecord
	v4Lens      []int
	v6Lens      []int
	status      GeoStatus
	cacheMu     sync.RWMutex
	cache       map[netip.Addr]geoCacheEntry
	cacheKeys   [geoCacheCapacity]netip.Addr
	cacheCursor int
	generation  atomic.Uint64
}

func NewGeoResolver(path string) *GeoResolver {
	r := &GeoResolver{status: GeoStatus{Path: path, CacheCapacity: geoCacheCapacity}, cache: make(map[netip.Addr]geoCacheEntry, geoCacheCapacity)}
	if strings.TrimSpace(path) == "" {
		r.status.LastError = "GeoIP database not configured"
		return r
	}
	if err := r.Load(path); err != nil {
		r.status.LastError = err.Error()
	}
	return r
}

// Load consumes the local compact CSV format documented in docs/kinetic/geoip.md:
// network,country_code,country_name,latitude,longitude,asn,as_name
//
// The dataset is opened exactly once through the reparse-safe primitive; the
// sidecar SHA-256 is verified against the same handle and the CSV is then parsed
// from that same handle (DP-FIND-007). No second path-based open exists, so a
// file swapped in the verify window cannot be parsed.
func (r *GeoResolver) Load(path string) (err error) {
	file, err := openGeoIPRegularFile(path)
	if err != nil {
		return fmt.Errorf("geoip database: %w", err)
	}
	defer cleanup.CloseInto(&err, file)
	before, err := file.Stat()
	if err != nil {
		return fmt.Errorf("geoip database: %w", err)
	}
	if before.Size() <= 0 || before.Size() > maxGeoIPCSVBytes {
		return fmt.Errorf("geoip database size outside limit: %d bytes", before.Size())
	}
	if err := verifyGeoSidecar(file, path); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("geoip database: %w", err)
	}
	reader := csv.NewReader(io.LimitReader(file, maxGeoIPCSVBytes+1))
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true
	v4 := make(map[int]map[netip.Addr]GeoRecord)
	v6 := make(map[int]map[netip.Addr]GeoRecord)
	lengths4 := make(map[int]struct{})
	lengths6 := make(map[int]struct{})
	count := 0
	row := 0
	for {
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return fmt.Errorf("geoip CSV row %d: %w", row+1, readErr)
		}
		row++
		if len(record) == 0 {
			continue
		}
		if row == 1 && strings.EqualFold(strings.TrimSpace(record[0]), "network") {
			continue
		}
		if len(record) < 5 {
			return fmt.Errorf("geoip CSV row %d requires at least 5 columns", row)
		}
		if count >= maxGeoIPEntries {
			return fmt.Errorf("geoip entry limit %d exceeded", maxGeoIPEntries)
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(record[0]))
		if err != nil {
			return fmt.Errorf("geoip CSV row %d invalid network: %w", row, err)
		}
		prefix = prefix.Masked()
		code := strings.ToUpper(strings.TrimSpace(record[1]))
		country := strings.TrimSpace(record[2])
		if !validCountryCode(code) || len(country) > 96 {
			return fmt.Errorf("geoip CSV row %d has invalid country metadata", row)
		}
		lat, err := strconv.ParseFloat(strings.TrimSpace(record[3]), 64)
		if err != nil || math.IsNaN(lat) || math.IsInf(lat, 0) || lat < -90 || lat > 90 {
			return fmt.Errorf("geoip CSV row %d has invalid latitude", row)
		}
		lon, err := strconv.ParseFloat(strings.TrimSpace(record[4]), 64)
		if err != nil || math.IsNaN(lon) || math.IsInf(lon, 0) || lon < -180 || lon > 180 {
			return fmt.Errorf("geoip CSV row %d has invalid longitude", row)
		}
		geo := GeoRecord{CountryCode: code, Country: country, Latitude: lat, Longitude: lon}
		if len(record) > 5 {
			geo.ASN = strings.TrimSpace(record[5])
			if len(geo.ASN) > 32 {
				geo.ASN = truncateUTF8Bytes(geo.ASN, 32)
			}
		}
		if len(record) > 6 {
			geo.ASName = strings.TrimSpace(record[6])
			if len(geo.ASName) > 128 {
				geo.ASName = truncateUTF8Bytes(geo.ASName, 128)
			}
		}
		bits := prefix.Bits()
		addr := prefix.Addr()
		if addr.Is4() {
			if v4[bits] == nil {
				v4[bits] = make(map[netip.Addr]GeoRecord)
			}
			v4[bits][addr] = geo
			lengths4[bits] = struct{}{}
		} else {
			if v6[bits] == nil {
				v6[bits] = make(map[netip.Addr]GeoRecord)
			}
			v6[bits][addr] = geo
			lengths6[bits] = struct{}{}
		}
		count++
	}
	after, err := file.Stat()
	if err != nil {
		return fmt.Errorf("geoip database: %w", err)
	}
	if after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		return errors.New("geoip database changed while it was verified and parsed")
	}
	v4Lens := sortedPrefixLengths(lengths4)
	v6Lens := sortedPrefixLengths(lengths6)
	now := time.Now().UTC()

	modified := after.ModTime().UTC()
	r.mu.Lock()
	r.v4, r.v6, r.v4Lens, r.v6Lens = v4, v6, v4Lens, v6Lens
	r.status = GeoStatus{Loaded: true, Path: path, Entries: count, LoadedAt: &now, SourceModifiedAt: &modified, CacheCapacity: geoCacheCapacity}
	r.generation.Add(1)
	r.mu.Unlock()
	r.cacheMu.Lock()
	r.cache = make(map[netip.Addr]geoCacheEntry, geoCacheCapacity)
	r.cacheKeys = [geoCacheCapacity]netip.Addr{}
	r.cacheCursor = 0
	r.cacheMu.Unlock()
	return nil
}

// verifyGeoSidecar is deliberately fail-closed. A stale or missing companion
// SHA-256 file must never silently turn unverified external data into the
// authoritative operator geolocation view. The dataset is hashed through the
// already-opened handle, never through a second path-based open.
func verifyGeoSidecar(file *os.File, path string) error {
	sidecar := path + ".sha256"
	data, err := readGeoIPSidecar(sidecar)
	if err != nil {
		return fmt.Errorf("geoip checksum missing: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 || len(fields[0]) != 64 {
		return errors.New("invalid geoip SHA-256 sidecar")
	}
	expected, err := hex.DecodeString(fields[0])
	if err != nil {
		return errors.New("invalid geoip SHA-256 sidecar")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxGeoIPCSVBytes+1)); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), expected) != 1 {
		return errors.New("geoip SHA-256 mismatch: dataset rejected")
	}
	return nil
}

func validCountryCode(value string) bool {
	if len(value) != 2 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

func sortedPrefixLengths(in map[int]struct{}) []int {
	out := make([]int, 0, len(in))
	for bits := range in {
		out = append(out, bits)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

func (r *GeoResolver) Lookup(ip net.IP) (GeoRecord, bool) {
	if r == nil || ip == nil {
		return GeoRecord{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return GeoRecord{}, false
	}
	addr = addr.Unmap()
	if !isPublicGeoAddr(addr) {
		return GeoRecord{}, false
	}

	currentGeneration := r.generation.Load()
	r.cacheMu.RLock()
	cached, cachedOK := r.cache[addr]
	r.cacheMu.RUnlock()
	if cachedOK && cached.Generation == currentGeneration {
		return cached.Record, cached.Found
	}

	r.mu.RLock()
	var table map[int]map[netip.Addr]GeoRecord
	var lengths []int
	if addr.Is4() {
		table, lengths = r.v4, r.v4Lens
	} else {
		table, lengths = r.v6, r.v6Lens
	}
	var result GeoRecord
	found := false
	for _, bits := range lengths {
		key := netip.PrefixFrom(addr, bits).Masked().Addr()
		if geo, exists := table[bits][key]; exists {
			result, found = geo, true
			break
		}
	}
	lookupGeneration := r.generation.Load()
	r.mu.RUnlock()
	r.cacheStore(addr, geoCacheEntry{Record: result, Found: found, Generation: lookupGeneration})
	return result, found
}

// LookupWithSpecial resolves public addresses through the database, and
// enriches private/special ranges with their RFC classification.
func (r *GeoResolver) LookupWithSpecial(ip net.IP) (GeoRecord, bool) {
	if r != nil {
		if record, ok := r.Lookup(ip); ok {
			return record, true
		}
	}
	return ClassifySpecial(ip)
}

func (r *GeoResolver) cacheStore(addr netip.Addr, entry geoCacheEntry) {
	if r == nil || !addr.IsValid() {
		return
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if r.cache == nil {
		r.cache = make(map[netip.Addr]geoCacheEntry, geoCacheCapacity)
	}
	if _, exists := r.cache[addr]; exists {
		r.cache[addr] = entry
		return
	}
	if len(r.cache) >= geoCacheCapacity {
		old := r.cacheKeys[r.cacheCursor]
		if old.IsValid() {
			delete(r.cache, old)
		}
	}
	r.cache[addr] = entry
	r.cacheKeys[r.cacheCursor] = addr
	r.cacheCursor = (r.cacheCursor + 1) % geoCacheCapacity
}

func (r *GeoResolver) Status() GeoStatus {
	if r == nil {
		return GeoStatus{CacheCapacity: geoCacheCapacity, LastError: "GeoIP resolver unavailable"}
	}
	r.mu.RLock()
	status := r.status
	r.mu.RUnlock()
	r.cacheMu.RLock()
	status.CacheEntries = len(r.cache)
	r.cacheMu.RUnlock()
	status.CacheCapacity = geoCacheCapacity
	return status
}

func truncateUTF8Bytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := []byte(s[:maxBytes])
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return strings.TrimSpace(string(b))
}
