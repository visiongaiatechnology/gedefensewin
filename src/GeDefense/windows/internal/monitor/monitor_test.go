// STATUS: DIAMANT VGT SUPREME
package monitor

import (
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
)

func TestHealthyRequiresDefenderCloudAndFreshSignatures(t *testing.T) {
	baseline := hardening.Result{Defender: true, DefenderService: true, RealTimeProtection: true, BehaviorProtection: true, CloudProtection: true, NetworkProtection: true, Firewall: true, WindowsUpdate: true, SignatureAgeDays: 1}
	if !healthy(baseline) {
		t.Fatal("complete Defender baseline was classified as degraded")
	}
	baseline.CloudProtection = false
	if healthy(baseline) {
		t.Fatal("disabled cloud protection was classified as healthy")
	}
	baseline.CloudProtection = true
	baseline.SignatureAgeDays = 4
	if healthy(baseline) {
		t.Fatal("stale Defender signatures were classified as healthy")
	}
}
