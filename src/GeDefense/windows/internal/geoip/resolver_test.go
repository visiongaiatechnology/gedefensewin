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
