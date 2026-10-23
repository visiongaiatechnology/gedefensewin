// STATUS: DIAMANT VGT SUPREME
package geoip

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeoRejectsNonFiniteCoordinates(t *testing.T) {
	for _, row := range []string{
		"8.8.8.0/24,DE,Germany,NaN,10\n",
		"8.8.8.0/24,DE,Germany,50,NaN\n",
		"8.8.8.0/24,DE,Germany,+Inf,10\n",
		"8.8.8.0/24,DE,Germany,50,-Inf\n",
	} {
		path := filepath.Join(t.TempDir(), "geoip.csv")
		writeTestCSV(t, path, row)
		if resolver := NewGeoResolver(path); resolver.Status().Loaded {
			t.Fatalf("non-finite coordinate accepted: %q", strings.TrimSpace(row))
		}
	}
}

func TestGeoValidatesCountryCodeShape(t *testing.T) {
	for _, row := range []string{
		"8.8.8.0/24,1X,Nope,50,10\n",
		"8.8.8.0/24,U1,Nope,50,10\n",
		"8.8.8.0/24,USA,TooLong,50,10\n",
		"8.8.8.0/24,,Empty,50,10\n",
	} {
		path := filepath.Join(t.TempDir(), "geoip.csv")
		writeTestCSV(t, path, row)
		if resolver := NewGeoResolver(path); resolver.Status().Loaded {
			t.Fatalf("invalid country code accepted: %q", strings.TrimSpace(row))
		}
	}
	path := filepath.Join(t.TempDir(), "geoip.csv")
	writeTestCSV(t, path, "8.8.8.0/24,us,United States,37,-97,AS1,Provider\n")
	resolver := NewGeoResolver(path)
	if !resolver.Status().Loaded {
		t.Fatalf("lowercase country code rejected: %+v", resolver.Status())
	}
	record, ok := resolver.Lookup(net.ParseIP("8.8.8.8"))
	if !ok || record.CountryCode != "US" {
		t.Fatalf("country code not canonicalized: %+v %t", record, ok)
	}
}
