// STATUS: DIAMANT VGT SUPREME
package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
)

type Source interface {
	Audit(context.Context) (hardening.Result, error)
}

type Monitor struct {
	source   Source
	ledger   *evidence.Ledger
	interval time.Duration
}

func New(source Source, ledger *evidence.Ledger, interval time.Duration) *Monitor {
	if interval < time.Minute {
		interval = time.Minute
	}
	return &Monitor{source: source, ledger: ledger, interval: interval}
}

func (m *Monitor) Run(stop <-chan struct{}) {
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	previous := ""
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			result, err := m.source.Audit(ctx)
			cancel()
			if err != nil {
				_ = m.ledger.Append("defender.monitor", "telemetry", "unavailable")
			} else {
				current := fingerprint(result)
				if current != previous {
					state := "healthy"
					if !healthy(result) {
						state = "degraded"
					}
					_ = m.ledger.Append("defender.monitor", "protection-state", state)
					previous = current
				}
			}
			timer.Reset(m.interval)
		}
	}
}

func healthy(result hardening.Result) bool {
	return result.Defender && result.DefenderService && result.RealTimeProtection && result.BehaviorProtection && result.CloudProtection && result.NetworkProtection && result.Firewall && result.WindowsUpdate && result.SignatureAgeDays >= 0 && result.SignatureAgeDays <= 3
}

func fingerprint(result hardening.Result) string {
	return fmt.Sprintf("%t|%t|%t|%t|%t|%t|%t|%t|%d|%d|%d", result.Defender, result.DefenderService, result.RealTimeProtection, result.BehaviorProtection, result.CloudProtection, result.NetworkProtection, result.Firewall, result.WindowsUpdate, result.ASRRules, result.ASRBlockRules, result.SignatureAgeDays)
}
