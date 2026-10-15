// STATUS: PLATIN
package server

import (
	"context"
	"net/http"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
)

type healthCheck struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}
type healthReport struct {
	CheckedUTC time.Time     `json:"checkedUtc"`
	Healthy    bool          `json:"healthy"`
	Checks     []healthCheck `json:"checks"`
}

// healthRefresh measures OS state after reconciliation, bypassing the posture cache.
func (s *Server) healthRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	posture, err := s.engine.Audit(ctx)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Windows-Sicherheitsstatus konnte nicht aktualisiert werden")
		return
	}
	report := evaluateHealth(posture, s.mhx.Status(), s.ledger.Verify() == nil)
	s.writeJSON(w, http.StatusOK, report)
}

func evaluateHealth(p hardening.Result, m mhx.Status, evidenceValid bool) healthReport {
	report := healthReport{CheckedUTC: time.Now().UTC(), Healthy: true, Checks: make([]healthCheck, 0, 7)}
	add := func(id, label string, ok bool, good, bad string) {
		check := healthCheck{ID: id, Label: label, State: "healthy", Detail: good}
		if !ok {
			check.State = "attention"
			check.Detail = bad
			report.Healthy = false
		}
		report.Checks = append(report.Checks, check)
	}
	add("policy", "Schutzrichtlinie", m.ProtectionHealth == "VERIFIED" && !m.ProtectionVerifiedUTC.IsZero(),
		"Konfigurierter Schutzmodus angewendet und verifiziert.",
		"Richtlinie nicht verifiziert. Policy erneut synchronisieren; bei erneutem Fehler Installationsdiagnose prüfen.")
	add("defender", "Microsoft Defender", p.Defender && p.DefenderService && p.RealTimeProtection,
		"Dienst und Echtzeitschutz sind aktiv.",
		"Defender oder Echtzeitschutz ist nicht aktiv. Windows-Sicherheit und weitere Virenschutzanbieter prüfen.")
	add("firewall", "Windows Firewall", p.Firewall,
		"Firewall-Profile sind aktiv.",
		"Firewall-Konfiguration benötigt Aufmerksamkeit. Im Bereich Härtung die Firewall prüfen.")
	fresh := !m.TelemetryHeartbeatUTC.IsZero() && time.Since(m.TelemetryHeartbeatUTC) <= 10*time.Second
	add("telemetry", "Prozess- und Netzwerk-Telemetrie", m.Realtime && fresh && m.NetworkTelemetry == "NATIVE_TCP_OWNER_PID",
		"Prozesssensor und native Netzwerk-Erfassung antworten.",
		"Sensoren noch nicht bereit. Erneut prüfen; bei anhaltendem Fehler den GeDefense-Dienst prüfen.")
	ti := m.ThreatIntelligence
	add("intelligence", "Threat Intelligence", ti.Indicators > 0 && ti.BlockingFeedsTotal > 0 && ti.BlockingFeedsReady == ti.BlockingFeedsTotal && (ti.State == "CURRENT" || ti.State == "CACHED"),
		"Threat-Feeds und lokale Datenbasis sind verfügbar.",
		"Threat-Feeds fehlen, sind veraltet oder nur teilweise verfügbar. Verbindung prüfen und erneut synchronisieren.")
	te := m.ThreatEnforcement
	add("enforcement", "Threat-IP-Firewallregeln", te.State == "VERIFIED" && te.ActiveGeneration != "" && te.ActiveGeneration == ti.EnforcementGeneration,
		"Aktive Firewall-Generation stimmt mit der Datenbasis überein.",
		"Threat-IP-Regeln sind noch nicht vollständig verifiziert. Threat Intelligence erneut synchronisieren.")
	add("evidence", "Evidenz und Audit-Kette", evidenceValid,
		"Integrität der lokalen Evidenzkette bestätigt.",
		"Evidenzkette konnte nicht bestätigt werden. Installationsdiagnose prüfen; Daten nicht zurücksetzen.")
	return report
}
