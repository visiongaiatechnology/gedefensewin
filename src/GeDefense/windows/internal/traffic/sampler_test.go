package traffic

import (
	"errors"
	"testing"
	"time"
)

func TestSampling(t *testing.T) {
	s := NewSampler()
	at := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	x := s.Record(map[uint32]Counters{3: {1000, 3000}}, at, nil)
	if x.State != "WARMING_UP" {
		t.Fatal(x)
	}
	x = s.Record(map[uint32]Counters{3: {3500, 5000}}, at.Add(2*time.Second), nil)
	if x.State != "LIVE" || x.ReceivedBytesPerSec != 1250 || x.SentBytesPerSec != 1000 {
		t.Fatal(x)
	}
	x = s.Record(map[uint32]Counters{3: {12, 30}}, at.Add(4*time.Second), nil)
	if x.ReceivedBytesPerSec != 0 || x.SentBytesPerSec != 0 {
		t.Fatal("counter rollover/ reset cannot create bogus spike", x)
	}
}
func TestDegraded(t *testing.T) {
	s := NewSampler()
	x := s.Record(nil, time.Now(), errors.New("unavailable"))
	if x.State != "UNAVAILABLE" {
		t.Fatal(x)
	}
}
