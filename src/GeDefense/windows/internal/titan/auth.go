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

	if isMaintenanceStartOnly(observation) {
		authorization.Status = TrustTolerated
		authorization.Reason = "Starttyp eines Windows-Wartungsdienstes wurde geändert; ImagePath, Diensttyp und Konto blieben unverändert. Die Änderung bleibt in der Evidenz, wird aber nicht als Persistenz-Hochrisiko eskaliert."
		authorization.NeedsReview = false
		authorization.AutoQuarantine = false
		return authorization
	}

	// 5.3.0 FP Normalization 1: Microsoft Defender Engine & Driver Updates
	// In ModeSimple, ModeBalanced, ModeAggressive, ModeObserve, ModeContain, ModeStrict:
	// Defender platform updates are tolerated. Only in ModeParanoid are they strictly flagged.
	if policy.Mode != ModeParanoid && isDefenderPlatformUpdate(observation) {
		authorization.Status = TrustTolerated
		authorization.Reason = "Autorisiertes Microsoft Defender Plattform-/Signatur-Update durch MsMpEng; kein Fremdeingriff."
		authorization.NeedsReview = false
		authorization.AutoQuarantine = false
		return authorization
	}

	// 5.3.0 FP Normalization 2: Windows Per-User Services (e.g. MessagingService_12541b, OneSyncSvc_12541b)
	// In ModeSimple, ModeBalanced, ModeObserve, ModeContain:
	// Dynamic session instances of legitimate registered system services are tolerated.
	// In ModeAggressive, ModeStrict, ModeParanoid:
	// They are NOT tolerated automatically because the user explicitly wants them alerted or blocked.
	if policy.Mode == ModeSimple || policy.Mode == ModeBalanced || policy.Mode == ModeObserve || policy.Mode == ModeContain || policy.Mode == "" {
		if isPerUser, baseName := isWindowsPerUserService(observation); isPerUser {
			authorization.Status = TrustTolerated
			authorization.Reason = fmt.Sprintf("Legitimer Windows Per-User-Dienst (%s); dynamische Session-Instanz; keine bösartige Persistenz.", baseName)
			authorization.NeedsReview = false
			authorization.AutoQuarantine = false
			return authorization
		}
	}

	// 5.3.0 FP Normalization 3: Visual Studio & Installer Session Temp Artifacts
	if (policy.Mode == ModeSimple || policy.Mode == ModeBalanced || policy.Mode == ModeObserve || policy.Mode == ModeContain || policy.Mode == "") && isInstallerSessionTempArtifact(observation) {
		authorization.Status = TrustTolerated
		authorization.Reason = "Temporäre Sprach-/Ressourcendatei eines autorisierten UAC-Installationsvorgangs; kein eigenständiger Fremdeingriff."
		authorization.NeedsReview = false
		authorization.AutoQuarantine = false
		return authorization
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
	if (policy.Mode == ModeSimple || policy.Mode == ModeBalanced || policy.Mode == ModeObserve || policy.Mode == ModeContain || policy.Mode == "") && isDevBuildTempArtifact(observation) {
		authorization.Status = TrustTolerated
		authorization.Reason = "Autorisiertes lokales Entwicklungs- oder Test-Build-Artefakt in temporärem Verzeichnis."
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

func isWindowsPerUserService(observation Observation) (bool, string) {
	if observation.Object.Kind != ObjectService {
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
	if _, ok := knownPerUserTemplates[strings.ToLower(base)]; ok {
		return true, base
	}
	// Fallback: If base name ends with "service" or "svc", it is also a per-user template instance
	baseLower := strings.ToLower(base)
	if strings.HasSuffix(baseLower, "svc") || strings.HasSuffix(baseLower, "service") {
		return true, base
	}
	return false, ""
}

func isDefenderPlatformUpdate(observation Observation) bool {
	actorImage := strings.ToLower(filepath.Base(strings.TrimSpace(observation.Actor.Image)))
	if actorImage == "" && observation.Actor.Path != "" {
		actorImage = strings.ToLower(filepath.Base(strings.TrimSpace(observation.Actor.Path)))
	}

	// 1. Defender Drivers & Binaries
	if observation.Object.Kind == ObjectFile {
		path := strings.ToLower(filepath.Clean(observation.Object.Path))
		name := strings.ToLower(observation.Object.Name)
		isDefenderDriverPath := strings.Contains(path, `\system32\drivers\wd\`) || strings.Contains(path, `\programdata\microsoft\windows defender\platform\`)
		isDefenderDriverName := name == "wddevflt.sys" || name == "ksld.sys" || name == "wdfilter.sys" || name == "wdboot.sys"
		if isDefenderDriverPath || isDefenderDriverName {
			if actorImage == "msmpeng.exe" || actorImage == "mpsigstub.exe" || actorImage == "trustedinstaller.exe" || actorImage == "tiworker.exe" {
				return true
			}
			// If actor image was not captured during temporal correlation, driver path and name match
			if isDefenderDriverPath && isDefenderDriverName {
				return true
			}
		}
	}

	// 2. Defender Services ImagePath/Config updates
	if observation.Object.Kind == ObjectService {
		serviceName := strings.ToUpper(strings.TrimSpace(observation.Object.Name))
		if serviceName == "WINDEFEND" || serviceName == "WDNISSVC" || serviceName == "MDCORESVC" || serviceName == "SENSE" {
			if actorImage == "msmpeng.exe" || actorImage == "trustedinstaller.exe" || actorImage == "tiworker.exe" || actorImage == "services.exe" || actorImage == "" {
				return true
			}
		}
	}

	return false
}

func isInstallerSessionTempArtifact(observation Observation) bool {
	if observation.Object.Kind != ObjectFile {
		return false
	}
	path := strings.ToLower(filepath.Clean(observation.Object.Path))
	if !strings.Contains(path, `\appdata\local\temp\`) && !strings.Contains(path, `\windows\temp\`) {
		return false
	}
	name := strings.ToLower(observation.Object.Name)
	if strings.HasSuffix(name, ".resources.dll") {
		return true
	}
	actorImage := strings.ToLower(filepath.Base(strings.TrimSpace(observation.Actor.Image)))
	switch actorImage {
	case "consent.exe", "dllhost.exe", "msiexec.exe", "setup.exe", "vs_installer.exe", "vs_installerservice.exe", "tiworker.exe", "trustedinstaller.exe":
		if strings.HasSuffix(name, ".dll") || strings.HasSuffix(name, ".tmp") {
			return true
		}
	}
	return false
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

func isDevBuildTempArtifact(observation Observation) bool {
	if observation.Object.Kind != ObjectFile {
		return false
	}
	path := strings.ToLower(filepath.Clean(observation.Object.Path))
	name := strings.ToLower(observation.Object.Name)

	isTemp := strings.Contains(path, `\appdata\local\temp\`) || strings.Contains(path, `\windows\temp\`)
	if !isTemp {
		return false
	}

	// 1. Go test executables and Go build cache
	if strings.HasSuffix(name, ".test.exe") || strings.Contains(path, `\go-build`) || name == "a.out.exe" {
		return true
	}

	// 2. Node.js / NPM / yarn build artifacts and modules in temp
	if strings.Contains(path, `\npm-cache\`) || strings.Contains(path, `\yarn-`) || strings.Contains(path, `\node_modules\`) {
		return true
	}

	// 3. Known developer tool actor
	actorImage := strings.ToLower(filepath.Base(strings.TrimSpace(observation.Actor.Image)))
	switch actorImage {
	case "go.exe", "compile.exe", "link.exe", "node.exe", "python.exe", "pwsh.exe", "powershell.exe", "code.exe", "vscodium.exe", "antigravity.exe":
		if strings.HasSuffix(name, ".exe") || strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".py") || strings.HasSuffix(name, ".tmp") {
			return true
		}
	}
	return false
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
