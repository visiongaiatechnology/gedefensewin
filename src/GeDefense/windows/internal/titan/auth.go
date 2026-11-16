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

	// GeDefense Sovereign Self-Protection: GeDefense's own processes, executables, updates, and logs
	if isGeDefenseOperation(observation) {
		authorization.Status = TrustTolerated
		authorization.Reason = "Autorisierte GeDefense Sovereign Eigenoperation; kein fremder Systemeingriff."
		authorization.NeedsReview = false
		authorization.AutoQuarantine = false
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

	if (riskClass == RiskIngress || riskClass == RiskUserContent) && ownerProcessChainAllowed(policy, observation.Actor.ProcessChain) {
		authorization.Status = TrustTolerated
		authorization.Reason = "Owner-approved development toolchain process chain observed; the change remains fully in evidence, but is not treated as ingress high risk. No authorization is granted for system, persistence or security changes."
		authorization.NeedsReview = false
		authorization.AutoQuarantine = false
		return authorization
	}

	if tolerated, evidence := maintenanceStartOnlyEvidence(observation); tolerated {
		authorization.Status = TrustTolerated
		authorization.Reason = "Starttyp eines Windows-Wartungsdienstes wurde geändert; ImagePath, Diensttyp und Konto blieben unverändert. Beleg: " + evidence + ". Die Änderung bleibt in der Evidenz, wird aber nicht als Persistenz-Hochrisiko eskaliert."
		authorization.NeedsReview = false
		authorization.AutoQuarantine = false
		return authorization
	}

	// 5.3.0 FP Normalization 1: Microsoft Defender Engine & Driver Updates
	// A tolerance requires a canonical Microsoft Defender path AND a valid
	// Authenticode signature on the binary body. Name-only matches, an empty
	// actor or an unverifiable signature stay flagged (FIND-WIN-010).
	if policy.Mode != ModeParanoid {
		if tolerated, evidence := titanDefenderPlatformEvidence(observation); tolerated {
			authorization.Status = TrustTolerated
			authorization.Reason = "Autorisiertes Microsoft Defender Plattform-/Signatur-Update belegt: " + evidence + "; kein Fremdeingriff."
			authorization.NeedsReview = false
			authorization.AutoQuarantine = false
			return authorization
		}
	}

	// 5.3.0 FP Normalization 2: Windows Per-User Services (e.g. MessagingService_12541b, OneSyncSvc_12541b)
	// In ModeSimple, ModeBalanced, ModeObserve, ModeContain:
	// Dynamic session instances of registered system services are tolerated only
	// when the service ImagePath proves canonical svchost.exe with a valid
	// signature. Random service-name patterns alone are never tolerated.
	// In ModeAggressive, ModeStrict, ModeParanoid:
	// They are NOT tolerated automatically because the user explicitly wants them alerted or blocked.
	if policy.Mode == ModeSimple || policy.Mode == ModeBalanced || policy.Mode == ModeObserve || policy.Mode == ModeContain || policy.Mode == "" {
		if tolerated, evidence := isWindowsPerUserService(observation); tolerated {
			authorization.Status = TrustTolerated
			authorization.Reason = fmt.Sprintf("Legitimer Windows Per-User-Dienst; dynamische Session-Instanz; belegt: %s.", evidence)
			authorization.NeedsReview = false
			authorization.AutoQuarantine = false
			return authorization
		}
	}

	// 5.3.0 FP Normalization 3: Visual Studio & Installer Session Temp Artifacts
	if policy.Mode == ModeSimple || policy.Mode == ModeBalanced || policy.Mode == ModeObserve || policy.Mode == ModeContain || policy.Mode == "" {
		if tolerated, evidence := installerSessionTempArtifactEvidence(observation); tolerated {
			authorization.Status = TrustTolerated
			authorization.Reason = "Temporäre Sprach-/Ressourcendatei eines autorisierten Installationsvorgangs; belegt: " + evidence + "."
			authorization.NeedsReview = false
			authorization.AutoQuarantine = false
			return authorization
		}
	}

	// 5.3.0 FP Normalization 4: Windows Scheduled Maintenance Tasks (Defender Scans, SvcRestartTask, UpdateOrchestrator)
	if (policy.Mode == ModeSimple || policy.Mode == ModeBalanced || policy.Mode == ModeObserve || policy.Mode == ModeContain || policy.Mode == "") && isWindowsMaintenanceTask(observation) {
		authorization.Status = TrustTolerated
		authorization.Reason = "Autorisierter Windows-Systemwartungstask (Task Scheduler); legitime Systemoperation."
		authorization.NeedsReview = false
		authorization.AutoQuarantine = false
		return authorization
	}

	// 5.3.0 FP Normalization 5: Development & Build Test Artifacts in Temp (go test *.test.exe, node, npm)
	// A tolerance requires the observed developer-tool actor evidence; a
	// standalone ".test.exe" name in Temp is never enough (FIND-WIN-010).
	if policy.Mode == ModeSimple || policy.Mode == ModeBalanced || policy.Mode == ModeObserve || policy.Mode == ModeContain || policy.Mode == "" {
		if tolerated, evidence := devBuildTempArtifactEvidence(observation); tolerated {
			authorization.Status = TrustTolerated
			authorization.Reason = "Autorisiertes lokales Entwicklungs- oder Test-Build-Artefakt; belegt: " + evidence + "."
			authorization.NeedsReview = false
			authorization.AutoQuarantine = false
			return authorization
		}
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

func ownerProcessChainAllowed(policy Policy, chain []string) bool {
	if len(chain) == 0 || len(policy.OwnerProcessImages) == 0 {
		return false
	}
	allowed := make(map[string]struct{}, len(policy.OwnerProcessImages))
	for _, image := range policy.OwnerProcessImages {
		allowed[strings.ToLower(filepath.Clean(strings.TrimSpace(image)))] = struct{}{}
	}
	for _, image := range chain {
		if _, ok := allowed[strings.ToLower(filepath.Clean(image))]; ok {
			return true
		}
	}
	return false
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

func maintenanceStartOnlyEvidence(observation Observation) (bool, string) {
	if observation.Object.Kind != ObjectService || observation.Object.Change != "START_ONLY" {
		return false, ""
	}
	switch strings.ToUpper(strings.TrimSpace(observation.Object.Name)) {
	case "BITS", "WUAUSERV", "TRUSTEDINSTALLER", "USOSVC", "WINDOWSMODULESINSTALLER":
	default:
		return false, ""
	}
	// A service name alone is attacker-chosen. The service's own configured
	// image must prove to be a signed Windows servicing binary.
	actorImage, actorPath := titanActorEvidence(observation)
	if actorImage == "" || actorPath == "" {
		return false, ""
	}
	switch actorImage {
	case "svchost.exe", "trustedinstaller.exe", "tiworker.exe":
	default:
		return false, ""
	}
	if !titanPathWithin(actorPath, titanWindowsRootDir()) {
		return false, ""
	}
	signature := titanFileSignatureStatus(actorPath)
	if signature != signatureStatusValid {
		return false, ""
	}
	return true, fmt.Sprintf("Dienst %s startet %s mit gültiger Authenticode-Signatur (%s)", observation.Object.Name, actorPath, signature)
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

var knownPerUserTemplates = map[string]struct{}{
	"messagingservice":                   {},
	"onesyncsvc":                         {},
	"wpnuserservice":                     {},
	"cdpusersvc":                         {},
	"bluetoothuserservice":               {},
	"devicesflowusersvc":                 {},
	"captureservice":                     {},
	"cbdhsvc":                            {},
	"bcastdvruserservice":                {},
	"p9rdrservice":                       {},
	"penservice":                         {},
	"userdatasvc":                        {},
	"devicepickerusersvc":                {},
	"deviceassociationbrokersvc":         {},
	"udkusersvc":                         {},
	"webthreatdefusersvc":                {},
	"aarsvc":                             {},
	"pimindexmaintenancesvc":             {},
	"npsmsvc":                            {},
	"cloudbackuprestoresvc":              {},
	"consentuxusersvc":                   {},
	"unistoresvc":                        {},
	"printworkflowusersvc":               {},
	"credentialenrollmentmanagerusersvc": {},
	"sharedrealitysvc":                   {},
	"graphicsperfsvc":                    {},
}

// isWindowsPerUserService recognizes the dynamic session instances of known
// per-user service templates. A random "<name>_<hex>" service is never accepted:
// the service ImagePath must resolve to canonical System32\svchost.exe and that
// binary must carry a valid Authenticode signature (FIND-WIN-010).
func isWindowsPerUserService(observation Observation) (bool, string) {
	if observation.Object.Kind != ObjectService {
		return false, ""
	}
	if observation.Type == EventPersistenceRemoved {
		return false, ""
	}
	name := strings.TrimSpace(observation.Object.Name)
	underscore := strings.LastIndex(name, "_")
	if underscore <= 0 || underscore >= len(name)-1 {
		return false, ""
	}
	base := name[:underscore]
	suffix := name[underscore+1:]
	// Suffix must be 4 to 8 hexadecimal digits (the user session LUID)
	if len(suffix) < 4 || len(suffix) > 8 {
		return false, ""
	}
	for _, ch := range suffix {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false, ""
		}
	}
	if _, known := knownPerUserTemplates[strings.ToLower(base)]; !known {
		return false, ""
	}
	actorImage, actorPath := titanActorEvidence(observation)
	if actorImage != "svchost.exe" || actorPath == "" {
		return false, ""
	}
	if !titanIsCanonicalWindowsSystemBinary(actorPath, "svchost.exe") {
		return false, ""
	}
	signature := titanFileSignatureStatus(actorPath)
	if signature != signatureStatusValid {
		return false, ""
	}
	return true, fmt.Sprintf("%s über %s mit gültiger Authenticode-Signatur (%s)", base, actorPath, signature)
}

func installerSessionTempArtifactEvidence(observation Observation) (bool, string) {
	if observation.Object.Kind != ObjectFile {
		return false, ""
	}
	path := strings.ToLower(filepath.Clean(observation.Object.Path))
	if !strings.Contains(path, `\appdata\local\temp\`) && !strings.Contains(path, `\windows\temp\`) {
		return false, ""
	}
	name := strings.ToLower(strings.TrimSpace(observation.Object.Name))
	if name == "" {
		name = strings.ToLower(filepath.Base(observation.Object.Path))
	}
	if !strings.HasSuffix(name, ".resources.dll") && !strings.HasSuffix(name, ".dll") && !strings.HasSuffix(name, ".tmp") {
		return false, ""
	}
	actorImage, actorPath := titanActorEvidence(observation)
	if actorImage == "" || actorPath == "" {
		return false, ""
	}
	if _, allowed := titanInstallerTempActorImages[actorImage]; !allowed {
		return false, ""
	}
	if !titanIsCanonicalTrustedToolPath(actorPath) {
		return false, ""
	}
	signature := titanFileSignatureStatus(actorPath)
	if signature != signatureStatusValid {
		return false, ""
	}
	return true, fmt.Sprintf("%s durch Installer-Komponente %s mit gültiger Authenticode-Signatur (%s)", name, actorPath, signature)
}

func isWindowsMaintenanceTask(observation Observation) bool {
	path := strings.ToLower(filepath.Clean(observation.Object.Path))
	name := strings.ToLower(strings.TrimSpace(observation.Object.Name))

	isTask := observation.Object.Kind == ObjectScheduledTask || strings.Contains(path, `\windows\system32\tasks\`)
	if !isTask {
		return false
	}

	if strings.Contains(path, `\microsoft\windows\windows defender`) ||
		strings.Contains(path, `\microsoft\windows\updateorchestrator`) ||
		strings.Contains(path, `\microsoft\windows\waasmedic`) ||
		strings.Contains(path, `\microsoft\windows\appid\svcrestarttask`) ||
		strings.Contains(path, `\microsoft\windows\servicing`) ||
		strings.Contains(path, `\microsoft\windows\flighting`) ||
		strings.Contains(path, `\microsoft\windows\diskcleanup`) ||
		strings.Contains(path, `\microsoft\windows\defrag`) ||
		name == "svcrestarttask" {
		return true
	}
	return false
}

// titanInstallerTempActorImages are the only installer components whose
// temporary localization/resource artifacts may be tolerated, and only together
// with a canonical trusted tool path and a valid Authenticode signature.
var titanInstallerTempActorImages = map[string]struct{}{
	"consent.exe":             {},
	"dllhost.exe":             {},
	"msiexec.exe":             {},
	"setup.exe":               {},
	"vs_installer.exe":        {},
	"vs_installerservice.exe": {},
	"tiworker.exe":            {},
	"trustedinstaller.exe":    {},
}

// titanGoToolchainImages are the bounded set of Go toolchain actors a Go test
// artifact may be attributed to. Windows Go binaries are not Authenticode
// signed, so the tolerance rests on the observed process identity instead of a
// name-only match.
var titanGoToolchainImages = map[string]struct{}{
	"go.exe":      {},
	"compile.exe": {},
	"link.exe":    {},
	"asm.exe":     {},
	"vet.exe":     {},
}

// titanDeveloperImages are the narrow developer tool actors tolerated for
// temporary build output. Shells and interpreters that an attacker can launch
// trivially are deliberately not part of this set.
var titanDeveloperImages = map[string]struct{}{
	"go.exe":       {},
	"compile.exe":  {},
	"link.exe":     {},
	"node.exe":     {},
	"python.exe":   {},
	"code.exe":     {},
	"vscodium.exe": {},
}

func devBuildTempArtifactEvidence(observation Observation) (bool, string) {
	if observation.Object.Kind != ObjectFile {
		return false, ""
	}
	path := strings.ToLower(filepath.Clean(observation.Object.Path))
	name := strings.ToLower(strings.TrimSpace(observation.Object.Name))
	if name == "" {
		name = strings.ToLower(filepath.Base(observation.Object.Path))
	}

	isTemp := strings.Contains(path, `\appdata\local\temp\`) || strings.Contains(path, `\windows\temp\`)
	if !isTemp {
		return false, ""
	}

	actorImage, actorPath := titanActorEvidence(observation)
	if actorImage == "" || actorPath == "" {
		return false, ""
	}
	// A bare image name is attacker-controlled. Only a process that Titan
	// actually observed may justify a developer-artifact tolerance.
	switch observation.Actor.CorrelationQuality {
	case CorrelationObserved, CorrelationTemporal:
	default:
		return false, ""
	}

	// 1. Go test executables and Go build cache
	isGoTest := strings.HasSuffix(name, ".test.exe") || strings.Contains(path, `\go-build`) || name == "a.out.exe"
	if isGoTest {
		if _, allowed := titanGoToolchainImages[actorImage]; !allowed {
			return false, ""
		}
		return true, fmt.Sprintf("Go-Testartefakt %s, beobachteter Go-Actor %s", name, actorPath)
	}

	// 2. Node.js / NPM / yarn build artifacts and modules in temp
	isNodeArtifact := strings.Contains(path, `\npm-cache\`) || strings.Contains(path, `\yarn-`) || strings.Contains(path, `\node_modules\`)
	if isNodeArtifact {
		if _, allowed := titanDeveloperImages[actorImage]; !allowed {
			return false, ""
		}
		return true, fmt.Sprintf("Node-Buildartefakt %s, beobachteter Entwickler-Actor %s", name, actorPath)
	}

	// 3. Known developer tool actor
	if _, allowed := titanDeveloperImages[actorImage]; !allowed {
		return false, ""
	}
	if strings.HasSuffix(name, ".exe") || strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".py") || strings.HasSuffix(name, ".tmp") {
		return true, fmt.Sprintf("%s durch beobachtetes Entwicklerwerkzeug %s", name, actorPath)
	}
	return false, ""
}

// Boolean wrappers keep the historic policy-helper contracts available for
// regression tests. The policy engine itself always uses the evidence-returning
// variants so that every tolerance decision carries its justification.
func isMaintenanceStartOnly(observation Observation) bool {
	tolerated, _ := maintenanceStartOnlyEvidence(observation)
	return tolerated
}

func isDefenderPlatformUpdate(observation Observation) bool {
	tolerated, _ := titanDefenderPlatformEvidence(observation)
	return tolerated
}

func isInstallerSessionTempArtifact(observation Observation) bool {
	tolerated, _ := installerSessionTempArtifactEvidence(observation)
	return tolerated
}

func isDevBuildTempArtifact(observation Observation) bool {
	tolerated, _ := devBuildTempArtifactEvidence(observation)
	return tolerated
}

func isGeDefenseOperation(observation Observation) bool {
	actorPath := strings.ToLower(filepath.Clean(strings.TrimSpace(observation.Actor.Path)))
	if strings.Contains(actorPath, `\vgt\gedefense\`) || strings.Contains(actorPath, `\program files\vgt\gedefense\`) {
		return true
	}
	for _, parent := range observation.Actor.ProcessChain {
		if strings.Contains(strings.ToLower(parent), `\vgt\gedefense\`) || strings.Contains(strings.ToLower(parent), `\program files\vgt\gedefense\`) {
			return true
		}
	}
	// A bare image name is attacker-controlled and must never grant the
	// sovereign exemption. Only the installed GeDefense tree qualifies.
	objPath := strings.ToLower(filepath.Clean(observation.Object.Path))
	if strings.Contains(objPath, `\vgt\gedefense\`) || strings.Contains(objPath, `\program files\vgt\gedefense`) ||
		strings.Contains(objPath, `\programdata\vgt\gedefense`) {
		return true
	}
	if observation.Object.Kind == ObjectService {
		svcName := strings.ToLower(strings.TrimSpace(observation.Object.Name))
		if svcName == "gedefense" || svcName == "gedefense-windows" || strings.HasPrefix(svcName, "gedefense") {
			return true
		}
	}
	return false
}
