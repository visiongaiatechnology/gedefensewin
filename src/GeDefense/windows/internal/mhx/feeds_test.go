// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestParseThreatFeeds(t *testing.T) {
	plain, err := parsePlainFeed([]byte("# source\n1.2.3.4\n2606:4700:4700::1111\ninvalid\n"))
	if err != nil || len(plain) != 2 {
		t.Fatalf("plain parse failed: %v %v", plain, err)
	}
	jsonFeed := []byte("{\"cidr\":\"93.184.216.0/24\"}\n{\"cidr\":\"2606:4700::/32\"}\n{\"type\":\"metadata\",\"timestamp\":1787822042,\"copyright\":\"(c) 2026 The Spamhaus Project SLU\",\"terms\":\"https://www.spamhaus.org/drop/terms/\"}\n")
	prefixes, err := parseNDJSONFeed(jsonFeed)
	if err != nil || len(prefixes) != 2 {
		t.Fatalf("JSON parse failed: %v %v", prefixes, err)
	}
	attribution, err := parseNDJSONAttribution(jsonFeed, FeedAttribution{Name: "Spamhaus DROP IPv4", URL: "https://www.spamhaus.org/drop/drop_v4.json"})
	if err != nil || attribution.SourceTimestampUnix != 1787822042 || attribution.Copyright == "" || attribution.Terms == "" {
		t.Fatalf("attribution parse failed: %+v %v", attribution, err)
	}
}

func TestMalformedCIDRFailsClosed(t *testing.T) {
	if _, err := parseNDJSONFeed([]byte("{\"cidr\":\"999.1.1.1/24\"}\n")); err == nil {
		t.Fatal("invalid CIDR was accepted")
	}
}

func TestMissingThreatFeedAttributionFailsClosed(t *testing.T) {
	feed := []byte("{\"cidr\":\"10.20.0.0/16\"}\n")
	if _, err := parseNDJSONAttribution(feed, FeedAttribution{Name: "Spamhaus"}); err == nil {
		t.Fatal("missing attribution was accepted")
	}
}

func TestPrefixIndexMatchesIPv4AndIPv6(t *testing.T) {
	manager := &FeedManager{prefixIndex: buildPrefixIndex([]netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("2001:db8:abcd::/48"),
	})}
	for _, address := range []string{"10.20.55.3", "2001:db8:abcd::42"} {
		if !manager.Contains(netip.MustParseAddr(address)) {
			t.Fatalf("expected threat prefix match for %s", address)
		}
	}
	for _, address := range []string{"10.21.0.1", "2001:db8:abce::1"} {
		if manager.Contains(netip.MustParseAddr(address)) {
			t.Fatalf("unexpected threat prefix match for %s", address)
		}
	}
}

func TestThreatPrefixRejectsDangerousCoverage(t *testing.T) {
	for _, value := range []string{"0.0.0.0/0", "10.0.0.0/8", "100.64.0.0/10", "192.0.2.0/24", "::/0", "2001:db8::/32"} {
		if validThreatPrefix(netip.MustParsePrefix(value)) {
			t.Fatalf("dangerous or non-public prefix accepted: %s", value)
		}
	}
	for _, value := range []string{"1.1.1.0/24", "185.220.100.0/24", "2606:4700::/32"} {
		if !validThreatPrefix(netip.MustParsePrefix(value)) {
			t.Fatalf("public threat prefix rejected: %s", value)
		}
	}
}

func TestLiveThreatFeedSynchronization(t *testing.T) {
	if os.Getenv("VGT_MHX_FEED_INTEGRATION") != "1" {
		t.Skip("set VGT_MHX_FEED_INTEGRATION=1 for live feed validation")
	}
	manager, err := NewFeedManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := manager.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	if status.State != "CURRENT" || status.Indicators < 100 || len(status.Generation) != 64 {
		t.Fatalf("invalid live feed state: %+v", status)
	}
}
