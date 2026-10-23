package geoip

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func writeTestCSV(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(contents))
	if err := os.WriteFile(path+".sha256", []byte(fmt.Sprintf("%x  geoip.csv\n", hash)), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestGeoLookupAndPrivacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.csv")
	writeTestCSV(t, path, "network,country_code,country_name,latitude,longitude,asn,as_name\n8.8.0.0/16,US,United States,37,-97,AS1,Test Provider\n8.8.8.0/24,DE,Germany,50,10,AS2,More Specific\n10.0.0.0/8,RU,Russia,50,50,AS9,Should Never Match\n")
	resolver := NewGeoResolver(path)
	if !resolver.Status().Loaded {
		t.Fatalf("not loaded: %+v", resolver.Status())
	}
	record, ok := resolver.Lookup(net.ParseIP("8.8.8.8"))
	if !ok || record.CountryCode != "DE" || record.ASN != "AS2" {
		t.Fatalf("LPM failed: %+v %t", record, ok)
	}
	record, ok = resolver.Lookup(net.ParseIP("8.8.4.4"))
	if !ok || record.CountryCode != "US" {
		t.Fatalf("fallback failed: %+v %t", record, ok)
	}
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "203.0.113.5", "::1", "2001:db8::1"} {
		if _, ok := resolver.Lookup(net.ParseIP(ip)); ok {
			t.Errorf("special address geolocated: %s", ip)
		}
	}
}

func TestClassifySpecial(t *testing.T) {
	cases := []struct {
		ip       string
		wantCode string
		wantASN  string
	}{
		{"192.168.178.1", "LAN", "RFC 1918"},
		{"10.20.30.40", "LAN", "RFC 1918"},
		{"172.20.1.1", "LAN", "RFC 1918"},
		{"127.0.0.1", "HOST", "RFC 1122"},
		{"::1", "HOST", "RFC 1122"},
		{"169.254.1.2", "LINK", "RFC 3927"},
		{"100.64.0.1", "ISP", "RFC 6598"},
		{"224.0.0.1", "MCAST", "RFC 5771"},
		{"fc00::1", "ULA", "RFC 4193"},
	}
	for _, tc := range cases {
		record, ok := ClassifySpecial(net.ParseIP(tc.ip))
		if !ok || record.CountryCode != tc.wantCode || record.ASN != tc.wantASN {
			t.Errorf("ClassifySpecial(%s) = (%+v, %v), want code %s, asn %s", tc.ip, record, ok, tc.wantCode, tc.wantASN)
		}
		if record.Latitude != 0 || record.Longitude != 0 {
			t.Errorf("ClassifySpecial(%s) gave non-zero coordinates: %v,%v", tc.ip, record.Latitude, record.Longitude)
		}
	}
	if _, ok := ClassifySpecial(net.ParseIP("8.8.8.8")); ok {
		t.Error("ClassifySpecial reported true for public address 8.8.8.8")
	}
}

func TestGeoRejectsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.csv")
	writeTestCSV(t, path, "8.8.8.0/24,DE,Germany,900,12\n")
	if r := NewGeoResolver(path); r.Status().Loaded {
		t.Fatal("malformed CSV accepted")
	}
}
func TestGeoTamperedDataRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.csv")
	content := "network,country_code,country_name,latitude,longitude,asn,as_name\n8.8.8.0/24,US,United States,37,-97,AS1,Provider\n"
	writeTestCSV(t, path, content)
	if err := os.WriteFile(path, []byte(content+" "), 0600); err != nil {
		t.Fatal(err)
	}
	if r := NewGeoResolver(path); r.Status().Loaded {
		t.Fatal("tampered database accepted")
	}
}
func TestFullCSVIfProvided(t *testing.T) {
	path := os.Getenv("GEDEFENSE_GEOIP_CSV")
	if path == "" {
		t.Skip("optional full dataset test")
	}
	r := NewGeoResolver(path)
	if !r.Status().Loaded {
		t.Fatalf("full database invalid: %+v", r.Status())
	}
	t.Logf("loaded %d prefixes", r.Status().Entries)
	if r.Status().Entries < 100000 {
		t.Fatalf("unexpectedly small dataset %d", r.Status().Entries)
	}
}
