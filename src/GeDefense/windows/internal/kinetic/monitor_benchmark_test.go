// STATUS: PLATIN
package kinetic

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkPortlessObservation(b *testing.B) {
	m := NewMonitor()
	now := time.Now().UTC()
	m.ObserveBlockedInbound("8.8.8.8", 0, now)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ObserveBlockedInbound("8.8.8.8", 0, now)
	}
}

func BenchmarkFullSourceSnapshot(b *testing.B) {
	m := NewMonitor()
	now := time.Now().UTC()
	for i := 0; i < maxSources; i++ {
		m.ObserveBlockedInbound(fmt.Sprintf("10.%d.%d.%d", i/65025, (i/255)%255, i%255+1), 0, now.Add(time.Duration(i)))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.SourceSnapshot(250)
	}
}
