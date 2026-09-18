// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"testing"
	"time"
)

func TestBoundedDedupeSuppressesWithinTTL(t *testing.T) {
	cache := newBoundedDedupe(2)
	now := time.Unix(100, 0)
	if !cache.Admit("a", now, time.Minute) {
		t.Fatal("first observation was not admitted")
	}
	if cache.Admit("a", now.Add(30*time.Second), time.Minute) {
		t.Fatal("duplicate inside TTL was admitted")
	}
	if !cache.Admit("a", now.Add(61*time.Second), time.Minute) {
		t.Fatal("expired observation was not admitted")
	}
}

func TestBoundedDedupeEvictsInsteadOfBlindingNewKeys(t *testing.T) {
	cache := newBoundedDedupe(2)
	now := time.Unix(100, 0)
	if !cache.Admit("a", now, time.Hour) || !cache.Admit("b", now, time.Hour) {
		t.Fatal("initial cache population failed")
	}
	if !cache.Admit("c", now, time.Hour) {
		t.Fatal("new key was dropped when bounded cache was full")
	}
	if got := len(cache.index); got != 2 {
		t.Fatalf("cache cardinality = %d, want 2", got)
	}
	if _, exists := cache.index["a"]; exists {
		t.Fatal("round-robin eviction did not remove the oldest slot")
	}
}
