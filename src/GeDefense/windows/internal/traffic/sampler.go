package traffic

import (
	"errors"
	"sync"
	"time"
)

// Counters are aggregate interface octets. They are not WFP packet capture.
type Counters struct{ Rx, Tx uint64 }
type Sample struct {
	State               string    `json:"state"`
	ReceivedBytesPerSec uint64    `json:"receivedBytesPerSec"`
	SentBytesPerSec     uint64    `json:"sentBytesPerSec"`
	ObservedUTC         time.Time `json:"observedUtc"`
	Source              string    `json:"source"`
}
type Sampler struct {
	mu         sync.Mutex
	previous   map[uint32]Counters
	last       time.Time
	lastSample Sample
}

func NewSampler() *Sampler {
	return &Sampler{previous: map[uint32]Counters{}, lastSample: Sample{State: "STARTING", Source: "WIN_IPHELPER_INTERFACE_OCTETS"}}
}
func (s *Sampler) Record(next map[uint32]Counters, at time.Time, err error) Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || next == nil || at.IsZero() {
		s.lastSample = Sample{State: "UNAVAILABLE", Source: "WIN_IPHELPER_INTERFACE_OCTETS"}
		return s.lastSample
	}
	result := Sample{State: "WARMING_UP", Source: "WIN_IPHELPER_INTERFACE_OCTETS", ObservedUTC: at}
	if !s.last.IsZero() && at.After(s.last) && at.Sub(s.last) <= 30*time.Second {
		elapsed := at.Sub(s.last).Seconds()
		result.State = "LIVE"
		for id, c := range next {
			if old, ok := s.previous[id]; ok {
				if c.Rx >= old.Rx {
					result.ReceivedBytesPerSec += uint64(float64(c.Rx-old.Rx) / elapsed)
				}
				if c.Tx >= old.Tx {
					result.SentBytesPerSec += uint64(float64(c.Tx-old.Tx) / elapsed)
				}
			}
		}
	}
	s.previous = next
	s.last = at
	s.lastSample = result
	return result
}
func (s *Sampler) Snapshot() Sample {
	if s == nil {
		return Sample{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSample
}

var ErrUnavailable = errors.New("network interface counters unavailable")
