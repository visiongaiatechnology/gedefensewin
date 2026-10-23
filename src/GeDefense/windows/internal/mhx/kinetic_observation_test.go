// STATUS: PLATIN
package mhx

import (
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
	"github.com/visiongaiatechnology/gedefense/windows/internal/traffic"
)

func TestWFPPortlessObservationReachesStatusWithoutFakeThreatMatch(t *testing.T) {
	feeds, err := threatintel.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{feeds: feeds, kineticMonitor: kinetic.NewMonitor(), trafficMonitor: traffic.NewSampler()}
	now := time.Now().UTC()
	for i := 0; i < 20; i++ {
		engine.evaluateWFPBlock(wfpBlockEvent{Direction: "Inbound", RemoteIP: "8.8.8.8", TimestampUTC: now.Add(time.Duration(i) * time.Millisecond), Protocol: 1})
	}
	status := engine.Status()
	if status.Kinetic.BlocksObserved != 20 || status.Kinetic.TrackedSources != 1 || len(status.KineticSources) != 1 || status.KineticSources[0].PortlessBlocks != 20 {
		t.Fatalf("real observation lost before the API model: %+v", status.KineticSources)
	}
	if status.Kinetic.BurstCandidates != 0 || status.KineticThreatCorrelations != 0 || status.KineticBlockedCorrelations != 0 || len(status.KineticIncidents) != 0 || len(engine.NetworkFindings(100)) != 0 {
		t.Fatal("a portless Windows block fabricated a burst, feed match or GeDefense enforcement")
	}
	engine.evaluateWFPBlock(wfpBlockEvent{Direction: "Outbound", RemoteIP: "1.1.1.1", TimestampUTC: now, LocalPort: 443})
	if engine.Status().Kinetic.BlocksObserved != 20 {
		t.Fatal("outbound event represented as ingress")
	}
}
