// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Evaluate applies the owner policy to one observation. It returns only the
// conclusion supported by the observation and the configured policy; missing
// actor or network evidence lowers confidence but is never invented.
func Evaluate(policy Policy, store *PolicyStore, observation Observation, now time.Time, recentHighRisk int) Authorization {
	riskClass := classifyObject(observation)
	fileType := observation.Object.FileType
	if fileType == "" && observation.Object.Kind == ObjectFile {
		fileType = classifyFile(observation.Object.Path)
		observation.Object.FileType = fileType
	}
	score := baseRiskScore(riskClass)
	reasons := []string{riskReason(riskClass)}
	if isRiskyType(fileType) {
		score += 18
		reasons = append(reasons, "ausführbarer oder skriptfähiger Dateityp")
	}
	if observation.Type == EventFileCreated || observation.Type == EventPersistenceAdded {
		score += 8
		reasons = append(reasons, "neu angelegtes Objekt")
	}
	if observation.Type == EventSecurityDowngrade || observation.Type == EventSecurityChanged || observation.Type == EventBootChanged {
		score += 20
		reasons = append(reasons, "sicherheitskritische Konfiguration")
	}
	if observation.Actor.CorrelationQuality == CorrelationNone || observation.Actor.PID == 0 {
		score += 4
		reasons = append(reasons, "keine direkte Prozesszuordnung beobachtet")
	}
	if observation.Network.CorrelationQuality == CorrelationTemporal && riskClass == RiskIngress {
		score += 7
		reasons = append(reasons, "zeitliche Nähe zu einem Remote-Kontext")
	}
	if score > 100 {
		score = 100
	}

	authorization := Authorization{
		RiskClass:  riskClass,
		PolicyMode: policy.Mode,
		RiskScore:  score,
		Reason:     strings.Join(reasons, "; "),
	}

	if observation.Type == EventSensorHealth || observation.Type == EventSelfIntegrity || observation.Type == EventReviewed {
		authorization.Status = TrustTolerated
		authorization.Reason = "Titan-Telemetrie, kein fremder Systemeingriff"
		authorization.NeedsReview = false
		return authorization
	}

	if store != nil && observation.Object.Path != "" {
		if permit := store.ConsumePermit(observation.Object.Path, observation.Object.SHA256, string(observation.Type), now); permit != nil {
			authorization.Status = TrustAuthorized
			authorization.MatchedGrant = permit.ID
			authorization.Reason = "gültige, begrenzte Besitzer-Freigabe angewendet"
			authorization.NeedsReview = false
			return authorization
		}
	}

	if store != nil && observation.Object.Path != "" && observation.Object.Kind == ObjectFile &&
		(riskClass == RiskIngress || riskClass == RiskUserContent) && store.IsDevelopmentPath(observation.Object.Path) {
		authorization.Status = TrustTolerated
		authorization.Reason = "Owner hat diesen Baum als Entwicklungs-/Build-Baum markiert; die Änderung bleibt vollständig in der Evidenz, wird aber nicht als Ingress-Hochrisiko eskaliert."
		authorization.NeedsReview = false
		authorization.AutoQuarantine = false
		return authorization
	}

	if isMaintenanceStartOnly(observation) {
		authorization.Status = TrustTolerated
		authorization.Reason = "Starttyp eines Windows-Wartungsdienstes wurde geändert; ImagePath, Diensttyp und Konto blieben unverändert. Die Änderung bleibt in der Evidenz, wird aber nicht als Persistenz-Hochrisiko eskaliert."
		authorization.NeedsReview = false
		authorization.AutoQuarantine = false
		return authorization
	}

	if highRisk(riskClass, observation.Type, fileType) {
		authorization.Status = TrustUnexpected
		authorization.NeedsReview = true
		if riskClass == RiskSecurity && observation.Type == EventSecurityDowngrade {
			authorization.Status = TrustCompromised
			authorization.NeedsReview = true
			authorization.Reason += "; sicherheitskritischer Schutz wurde abgeschwächt"
		} else if score >= 60 && recentHighRisk >= 2 {
			authorization.Status = TrustCompromised
			authorization.NeedsReview = true
			authorization.Reason += "; mehrere unabhängige Hochrisikoänderungen im Beobachtungsfenster"
		}
		authorization.AutoQuarantine = policy.AutoQuarantine && policy.Mode != ModeObserve && observation.Type != EventFileDeleted && observation.Type != EventPersistenceRemoved && observation.Type != EventSecurityDowngrade && isRiskyType(fileType)
		return authorization
	}

	if score >= 35 && (riskClass == RiskPersistence || riskClass == RiskSecurity || riskClass == RiskBoot || isRiskyType(fileType)) {
		authorization.Status = TrustUnexpected
		authorization.NeedsReview = false
		return authorization
	}
	authorization.Status = TrustTolerated
	authorization.NeedsReview = false
	return authorization
}

func classifyObject(observation Observation) RiskClass {
	switch observation.Type {
	case EventPersistenceAdded, EventPersistenceChanged, EventPersistenceRemoved:
		return RiskPersistence
	case EventSecurityChanged, EventSecurityDowngrade:
		return RiskSecurity
	case EventBootChanged:
		return RiskBoot
	case EventSensorHealth, EventSelfIntegrity, EventReviewed:
		return RiskTitan
	}
	switch observation.Object.Kind {
	case ObjectService, ObjectScheduledTask:
		return RiskPersistence
	case ObjectRegistryValue, ObjectRegistryKey:
		if strings.Contains(strings.ToLower(observation.Object.Path), `microsoft\windows\currentversion\run`) {
			return RiskPersistence
		}
		return RiskSystem
	case ObjectBoot:
		return RiskBoot
	}
	return classifyPath(observation.Object.Path)
}

func classifyPath(path string) RiskClass {
	if path == "" {
		return RiskUnknown
	}
	normalized := strings.ToLower(filepath.Clean(path))
	switch {
	case strings.Contains(normalized, `\windows\system32\tasks`),
		strings.Contains(normalized, `\windows\system32\groupolicy`),
		strings.Contains(normalized, `\start menu\programs\startup`),
		strings.Contains(normalized, `\programdata\microsoft\windows\start menu\programs\startup`):
		return RiskPersistence
	case strings.Contains(normalized, `\windows\system32\drivers`),
		strings.Contains(normalized, `\windows\system32\codeintegrity`):
		return RiskSystem
	case strings.Contains(normalized, `\users\`) && (strings.Contains(normalized, `\downloads\`) ||
		strings.Contains(normalized, `\desktop\`) || strings.Contains(normalized, `\appdata\local\temp\`)),
		strings.Contains(normalized, `\users\public\`),
		strings.Contains(normalized, `\windows\temp\`):
		return RiskIngress
	case strings.HasPrefix(normalized, `c:\windows\`), strings.HasPrefix(normalized, `c:\program files\`),
		strings.HasPrefix(normalized, `c:\program files (x86)\`), strings.HasPrefix(normalized, `c:\programdata\`):
		return RiskSystem
	default:
		return RiskUserContent
	}
}

func classifyFile(path string) string {
	extension := strings.ToLower(filepath.Ext(path))
	switch extension {
	case ".exe", ".com", ".scr", ".pif", ".msi", ".msp":
		return "EXECUTABLE"
	case ".dll", ".sys", ".drv", ".ocx", ".cpl":
		return "DRIVER"
	case ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".py", ".sh", ".jar":
		return "SCRIPT"
	case ".lnk", ".url":
		return "SHORTCUT"
	case ".zip", ".7z", ".rar", ".iso", ".cab", ".msix", ".appx":
		return "ARCHIVE"
	default:
		return "OTHER"
	}
}

func isMaintenanceStartOnly(observation Observation) bool {
	if observation.Object.Kind != ObjectService || observation.Object.Change != "START_ONLY" {
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(observation.Object.Name)) {
	case "BITS", "WUAUSERV", "TRUSTEDINSTALLER", "USOSVC", "WINDOWSMODULESINSTALLER":
		return true
	default:
		return false
	}
}

func isRiskyType(fileType string) bool {
	return fileType == "EXECUTABLE" || fileType == "SCRIPT" || fileType == "DRIVER" || fileType == "SHORTCUT"
}

func baseRiskScore(class RiskClass) int {
	switch class {
	case RiskSecurity:
		return 58
	case RiskBoot:
		return 62
	case RiskPersistence:
		return 52
	case RiskSystem:
		return 36
	case RiskIngress:
		return 28
	case RiskTitan:
		return 10
	case RiskUserContent:
		return 8
	default:
		return 12
	}
}

func riskReason(class RiskClass) string {
	switch class {
	case RiskSecurity:
		return "Sicherheitskonfiguration betroffen"
	case RiskBoot:
		return "Boot- oder Vertrauenskette betroffen"
	case RiskPersistence:
		return "Persistenz- oder Startmechanismus betroffen"
	case RiskSystem:
		return "Systemkomponente betroffen"
	case RiskIngress:
		return "benutzerbeschreibbarer Ingress-Pfad betroffen"
	case RiskTitan:
		return "Titan-eigene Telemetrie"
	case RiskUserContent:
		return "Benutzerinhalt betroffen"
	default:
		return "Risikoklasse unbekannt"
	}
}

func highRisk(class RiskClass, eventType EventType, fileType string) bool {
	if eventType == EventSecurityDowngrade || eventType == EventBootChanged {
		return true
	}
	if class == RiskPersistence || class == RiskSecurity || class == RiskBoot {
		return true
	}
	if class == RiskSystem && (isRiskyType(fileType) || eventType == EventFileDeleted) {
		return true
	}
	if class == RiskIngress && isRiskyType(fileType) && (eventType == EventFileCreated || eventType == EventFileRenamed) {
		return true
	}
	return false
}

func describeRisk(authorization Authorization) string {
	if authorization.MatchedGrant != "" {
		return fmt.Sprintf("%s · Freigabe %s", authorization.Status, authorization.MatchedGrant)
	}
	return fmt.Sprintf("%s · Risiko %d", authorization.Status, authorization.RiskScore)
}
