// STATUS: DIAMANT VGT SUPREME
// Package settings owns the persisted, strictly validated operator
// configuration of GeDefense Windows V5.
//
// Invariants:
//   - The on-disk document is written atomically (temporary file + atomic
//     replace) with restrictive permissions (0600) under a caller-supplied
//     absolute path.
//   - A missing, unreadable, partial or schema-incompatible document never
//     produces invented security state: the service fails safe to the
//     documented catalog defaults and reports the recovery in Snapshot.State.
//   - Every accepted value is validated against the static catalog before it is
//     persisted or handed to an injected Applier. Unknown fields are rejected.
//   - A failed applier call never persists a success timestamp.
//   - Protection levels are explicit: monitor/guarded/sovereign carry hard
//     security floors. A profile that cannot satisfy its level floor is
//     rejected; a custom profile that weakens the active built-in level is only
//     reachable through an explicit custom activation phrase.
//
// The package has no external dependencies and no knowledge of the concrete
// hardening/MHX/Kinetic/Threat-Intelligence engines: the Lead-owned wiring
// injects an Applier (and optionally an evidence ledger) through Options.
package settings

// SchemaVersion is the on-disk settings document schema.
const SchemaVersion = 1

// CatalogVersion identifies the static control catalog. It changes whenever a
// control is added, removed or its meaning changes.
const CatalogVersion = "5.0.0"

const (
	// SectionDefender covers Microsoft Defender preferences.
	SectionDefender = "defender"
	// SectionFirewall covers Windows Firewall profile behavior.
	SectionFirewall = "firewall"
	// SectionHardening covers the Windows baseline hardening components.
	SectionHardening = "hardening"
	// SectionMHX covers MHX realtime response behavior.
	SectionMHX = "mhx"
	// SectionKinetic covers Kinetic Defense observation thresholds.
	SectionKinetic = "kinetic"
	// SectionThreatIntelligence covers threat feed polling and policy.
	SectionThreatIntelligence = "threatIntelligence"
	// SectionStartup covers service/tray/startup behavior.
	SectionStartup = "startup"
	// SectionNotifications covers operator notification behavior.
	SectionNotifications = "notifications"
)

const (
	// TypeBool is a strict JSON boolean control.
	TypeBool = "bool"
	// TypeInteger is a bounded whole-number control.
	TypeInteger = "int"
	// TypeEnum is a control with a fixed option whitelist.
	TypeEnum = "enum"
	// TypeStringList is a bounded list of validated strings.
	TypeStringList = "stringList"
)

const (
	// RiskLow is informational.
	RiskLow = "LOW"
	// RiskMedium affects operator experience or audit quality.
	RiskMedium = "MEDIUM"
	// RiskHigh weakens a defense mechanism if lowered.
	RiskHigh = "HIGH"
	// RiskCritical weakens a core security invariant if lowered.
	RiskCritical = "CRITICAL"
)

const (
	// LevelMonitor observes without active response.
	LevelMonitor = "monitor"
	// LevelGuarded enforces the verified guarded baseline.
	LevelGuarded = "guarded"
	// LevelSovereign enforces the maximum verified baseline.
	LevelSovereign = "sovereign"
	// LevelCustom is an operator-defined, explicitly confirmed profile.
	LevelCustom = "custom"
)

const (
	// ConfirmationApplySettings is the literal phrase required for a direct
	// settings apply. It is deliberately not a default: the operator must send
	// it explicitly.
	ConfirmationApplySettings = "APPLY SETTINGS"
	// ConfirmationMonitor is the phrase required to activate the monitor level.
	ConfirmationMonitor = "RETURN TO MONITOR"
	// ConfirmationGuarded is the phrase required to activate guarded level.
	ConfirmationGuarded = "ACTIVATE GUARDED"
	// ConfirmationSovereign is the phrase required to activate sovereign level.
	ConfirmationSovereign = "SOVEREIGN DEFAULT DENY"
	// ConfirmationCustom is the phrase required to activate a custom profile.
	ConfirmationCustom = "APPLY CUSTOM PROFILE"
)

const (
	// StatePersisted means the values were loaded from a valid persisted file.
	StatePersisted = "persisted"
	// StateDefaults means no persisted file exists yet; documented defaults are
	// active and nothing has been written.
	StateDefaults = "defaults"
	// StateRecovered means the persisted file was corrupt/partial/unsupported.
	// Documented defaults are active; the rejected file was preserved next to it
	// with the ".corrupt" suffix where possible.
	StateRecovered = "recovered"
)

const (
	minReasonLength = 8
	maxReasonLength = 512

	maxPersistedBytes = 256 << 10
	maxRequestValues  = 128
	maxProfiles       = 32
	maxNameLength     = 64
	maxDescription    = 256
	maxProfileValues  = 512
)

// Section is one settings page / persisted section.
type Section struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Order       int    `json:"order"`
}

// Level is the published protection level contract.
type Level struct {
	ID                string `json:"id"`
	Label             string `json:"label"`
	Description       string `json:"description"`
	Risk              string `json:"risk"`
	ResponseAuthority bool   `json:"responseAuthority"`
	Confirmation      string `json:"confirmation"`
	DefaultProfileID  string `json:"defaultProfileId,omitempty"`
}

// Control is one stable, catalogued setting.
type Control struct {
	ID              string   `json:"id"`
	Section         string   `json:"section"`
	Label           string   `json:"label"`
	Category        string   `json:"category"`
	Description     string   `json:"description"`
	Type            string   `json:"type"`
	Default         any      `json:"default"`
	Min             *int64   `json:"min,omitempty"`
	Max             *int64   `json:"max,omitempty"`
	Unit            string   `json:"unit,omitempty"`
	Options         []string `json:"options,omitempty"`
	Risk            string   `json:"risk"`
	RequiresRestart bool     `json:"requiresRestart"`
	// Levels lists the protection levels in which the control is
	// operator-configurable. Controls whose list does not contain the active
	// level keep their level baseline and reject direct applies.
	Levels []string `json:"levels"`

	maxItems  int
	maxLength int
	custom    func(any) (any, error)
}

// Catalog is the static UI contract for every settings control.
type Catalog struct {
	SchemaVersion  int       `json:"schemaVersion"`
	CatalogVersion string    `json:"catalogVersion"`
	Controls       []Control `json:"controls"`
	Sections       []Section `json:"sections"`
	Levels         []Level   `json:"levels"`
}

// CatalogDefinition returns a fresh copy of the static catalog.
func CatalogDefinition() Catalog {
	controls := allControls()
	return Catalog{
		SchemaVersion:  SchemaVersion,
		CatalogVersion: CatalogVersion,
		Controls:       controls,
		Sections:       sectionDefinitions(),
		Levels:         levelDefinitions(),
	}
}

// DefaultProfileID is the built-in profile that is active when no persisted
// state exists.
const DefaultProfileID = LevelGuarded

var allLevelIDs = []string{LevelMonitor, LevelGuarded, LevelSovereign, LevelCustom}

var responseLevelIDs = []string{LevelGuarded, LevelSovereign, LevelCustom}

func levelDefinitions() []Level {
	return []Level{
		{
			ID:                LevelMonitor,
			Label:             "Nur Überwachung",
			Description:       "Erkennt und protokolliert, erzwingt keine aktive Antwort. Defender-Echtzeitschutz und Firewall-Grundschutz bleiben verpflichtend.",
			Risk:              RiskMedium,
			ResponseAuthority: false,
			Confirmation:      ConfirmationMonitor,
			DefaultProfileID:  LevelMonitor,
		},
		{
			ID:                LevelGuarded,
			Label:             "Guarded",
			Description:       "Verifizierte Standardverteidigung: Echtzeitschutz, Verhaltensschutz, Netzwerkschutz, PUA, Controlled Folder Access, blockierende Threat-Intelligence-Feeds und begrenzte Prozessantwort.",
			Risk:              RiskHigh,
			ResponseAuthority: true,
			Confirmation:      ConfirmationGuarded,
			DefaultProfileID:  LevelGuarded,
		},
		{
			ID:                LevelSovereign,
			Label:             "Sovereign",
			Description:       "Maximalprofil: Guarded-Baseline plus Zero-Tolerance-Cloud, durchgesetzte Anwendungssteuerung, Netzwerk-Default-Deny, persistierte Kinetic-Bereitschaft und vollständige Hardening-Komponenten.",
			Risk:              RiskCritical,
			ResponseAuthority: true,
			Confirmation:      ConfirmationSovereign,
			DefaultProfileID:  LevelSovereign,
		},
		{
			ID:                LevelCustom,
			Label:             "Benutzerdefiniert",
			Description:       "Operator-definiertes Profil. Explizite Bestätigung erforderlich; das Profil darf Sicherheitsgrundwerte unterschreiten, wird aber im Snapshot als benutzerdefiniert ausgewiesen.",
			Risk:              RiskHigh,
			ResponseAuthority: true,
			Confirmation:      ConfirmationCustom,
		},
	}
}

func sectionDefinitions() []Section {
	return []Section{
		{ID: SectionDefender, Label: "Microsoft Defender", Description: "Echtzeitschutz, Cloud, Sample-Einwilligung, Netzwerkschutz, PUA, Controlled Folder Access und ASR-Regelaktionen.", Order: 1},
		{ID: SectionFirewall, Label: "Windows-Firewall", Description: "Profilzustände, eingehende Standardaktion, Benachrichtigungen und Protokollierung.", Order: 2},
		{ID: SectionHardening, Label: "Windows-Härtung", Description: "Ausgewählte Baseline-Komponenten, Rollback-Sicherung und Neustartverhalten.", Order: 3},
		{ID: SectionMHX, Label: "MHX XDR", Description: "Aggressivität, Schwellwerte, Prozessantwort, Anwendungs- und Netzwerkeinschränkungen.", Order: 4},
		{ID: SectionKinetic, Label: "Kinetic Defense", Description: "Persistierte Bereitschaft, Burst-Schwellen, automatische Deaktivierung und Benachrichtigungen.", Order: 5},
		{ID: SectionThreatIntelligence, Label: "Threat Intelligence", Description: "Abrufintervall, Feed-Aktionen, blockierende Abdeckung und geschützte Netze.", Order: 6},
		{ID: SectionStartup, Label: "Start & Hintergrund", Description: "Dienststart, Tray-Verhalten, Bereitschaftsprüfung und Health-Refresh.", Order: 7},
		{ID: SectionNotifications, Label: "Benachrichtigungen", Description: "Ereignisbenachrichtigungen, Startzusammenfassung, Ton und Detailtiefe.", Order: 8},
	}
}

func allControls() []Control {
	return append(defenderControls(), append(firewallControls(),
		append(hardeningControls(), append(mhxControls(),
			append(kineticControls(), append(threatIntelligenceControls(),
				append(startupControls(), notificationControls()...)...)...)...)...)...)...)
}

func newBool(id, label, category, description, risk string, def bool, levels []string) Control {
	section, _ := splitControlID(id)
	return Control{
		ID: id, Section: section, Label: label, Category: category,
		Description: description, Type: TypeBool, Default: def,
		Risk: risk, RequiresRestart: false, Levels: levels,
	}
}

func newInt(id, label, category, description, risk string, def, minimum, maximum int64, unit string, levels []string) Control {
	section, _ := splitControlID(id)
	minCopy, maxCopy := minimum, maximum
	return Control{
		ID: id, Section: section, Label: label, Category: category,
		Description: description, Type: TypeInteger, Default: int(def),
		Min: &minCopy, Max: &maxCopy, Unit: unit,
		Risk: risk, RequiresRestart: false, Levels: levels,
	}
}

func newEnum(id, label, category, description, risk, def string, options, levels []string) Control {
	section, _ := splitControlID(id)
	return Control{
		ID: id, Section: section, Label: label, Category: category,
		Description: description, Type: TypeEnum, Default: def,
		Options: options, Risk: risk, RequiresRestart: false, Levels: levels,
	}
}

func newStringList(id, label, category, description, risk string, def []string, maxItems, maxLength int, levels []string) Control {
	section, _ := splitControlID(id)
	defaults := make([]string, len(def))
	copy(defaults, def)
	return Control{
		ID: id, Section: section, Label: label, Category: category,
		Description: description, Type: TypeStringList, Default: defaults,
		Risk: risk, RequiresRestart: false, Levels: levels,
		maxItems: maxItems, maxLength: maxLength,
	}
}

func defenderControls() []Control {
	levels := allLevelIDs
	cloudLevels := []string{"default", "moderate", "high", "highPlus", "zeroTolerance"}
	sampleLevels := []string{"never", "safe", "always"}
	asr := newStringList("defender.asrRuleActions", "ASR-Regelaktionen", "DEFENDER", "Defender-ASR-Regel-UUID mit Aktion (block, audit, warn, disabled), Format 'regel-uuid:aktion'. Leer bedeutet VGT-Baseline (elf Regeln im Blockmodus).", RiskHigh, []string{}, 32, 128, levels)
	asr.custom = normalizeASRRules
	return []Control{
		newBool("defender.realtimeProtection", "Echtzeitschutz", "DEFENDER", "Microsoft Defender Echtzeitschutz für Dateien, Prozesse und Verhalten.", RiskCritical, true, levels),
		newBool("defender.behaviorProtection", "Verhaltensschutz", "DEFENDER", "Verhaltensüberwachung und -blockierung durch Defender.", RiskCritical, true, levels),
		newBool("defender.ioavProtection", "IOAV-Schutz", "DEFENDER", "Scan von Downloads und Anhängen durch Defender.", RiskHigh, true, levels),
		newBool("defender.tamperProtection", "Manipulationsschutz", "DEFENDER", "Verhindert lokale Deaktivierung der Defender-Schutzkomponenten.", RiskCritical, true, levels),
		newEnum("defender.cloudBlockLevel", "Cloud-Blockstufe", "DEFENDER", "Stärke der cloudbasierten Blockentscheidungen: default, moderate, high, highPlus oder zeroTolerance.", RiskHigh, "high", cloudLevels, levels),
		newEnum("defender.sampleSubmission", "Sample-Einwilligung", "DEFENDER", "Übermittlung von Beispieldateien an Microsoft: never, safe (nur sichere) oder always.", RiskMedium, "safe", sampleLevels, levels),
		newBool("defender.networkProtection", "Netzwerkschutz", "DEFENDER", "Blockiert bekannte schädliche IP-Adressen und Domains auf Netzwerkebene.", RiskHigh, true, levels),
		newBool("defender.puaProtection", "PUA-Schutz", "DEFENDER", "Blockiert potenziell unerwünschte Anwendungen.", RiskHigh, true, levels),
		newBool("defender.controlledFolderAccess", "Controlled Folder Access", "RANSOMWARE", "Schützt wichtige Ordner vor unbefugten Schreibzugriffen.", RiskHigh, true, levels),
		asr,
		newBool("defender.signatureUpdatesEnabled", "Signaturupdates", "DEFENDER", "Automatische Defender-Signatur- und Plattformupdates zulassen.", RiskHigh, true, levels),
	}
}

func firewallControls() []Control {
	levels := allLevelIDs
	actions := []string{"block", "allow"}
	return []Control{
		newBool("firewall.domainProfileEnabled", "Domänenprofil", "NETZWERK", "Windows-Firewall im Domänenprofil aktivieren.", RiskCritical, true, levels),
		newBool("firewall.privateProfileEnabled", "Privates Profil", "NETZWERK", "Windows-Firewall im privaten Profil aktivieren.", RiskCritical, true, levels),
		newBool("firewall.publicProfileEnabled", "Öffentliches Profil", "NETZWERK", "Windows-Firewall im öffentlichen Profil aktivieren.", RiskCritical, true, levels),
		newEnum("firewall.defaultInboundAction", "Eingehende Standardaktion", "NETZWERK", "Standardaktion für nicht explizit erlaubte eingehende Verbindungen.", RiskCritical, "block", actions, levels),
		newBool("firewall.notificationsEnabled", "Firewall-Benachrichtigungen", "NETZWERK", "Blockierte eingehende Verbindungen als Benachrichtigung anzeigen.", RiskLow, true, levels),
		newBool("firewall.loggingEnabled", "Firewall-Protokollierung", "NETZWERK", "Blockierte und erlaubte Verbindungen protokollieren.", RiskMedium, true, levels),
		newInt("firewall.logMaxSizeKB", "Protokollgröße", "NETZWERK", "Maximale Größe der Firewall-Protokolldatei.", RiskLow, 4096, 1024, 32767, "KB", levels),
		newBool("firewall.logDroppedPackets", "Verworfene Pakete protokollieren", "NETZWERK", "Auch verworfene Pakete in die Firewall-Protokollierung aufnehmen.", RiskLow, false, levels),
	}
}

func hardeningControls() []Control {
	levels := allLevelIDs
	components := newStringList("hardening.enabledComponents", "Baseline-Komponenten", "HÄRTUNG", "Aktive Härtungskomponenten. Leere Liste pausiert die Härtung und ist auf den Stufen Guarded/Sovereign nicht zulässig.", RiskMedium, append([]string(nil), hardeningComponentIDs...), len(hardeningComponentIDs), 64, levels)
	components.custom = normalizeHardeningComponents
	components.RequiresRestart = true
	return []Control{
		components,
		newBool("hardening.backupBaseline", "Baseline-Sicherung", "HÄRTUNG", "Vor Änderungen eine reversible Baseline-Sicherung anlegen.", RiskMedium, true, levels),
		newBool("hardening.allowReboot", "Neustart zulassen", "HÄRTUNG", "Die Härtung darf bei Bedarf einen Neustart auslösen.", RiskMedium, false, levels),
		newBool("hardening.driftMonitoring", "Drift-Überwachung", "HÄRTUNG", "Periodische Prüfung auf Abweichungen der Härtungs-Baseline.", RiskLow, true, levels),
	}
}

func mhxControls() []Control {
	levels := allLevelIDs
	responseLevels := responseLevelIDs
	aggr := []string{LevelMonitor, LevelGuarded, LevelSovereign, LevelCustom}
	restricted := newStringList("mhx.restrictedProcessNames", "Eingeschränkte Prozessnamen", "MHX", "Weitere Prozessnamen (Dateinamen, keine Pfade), die blockiert werden sollen.", RiskMedium, []string{}, 64, 64, responseLevels)
	restricted.custom = normalizeProcessNames
	controls := []Control{
		newEnum("mhx.aggressiveness", "Aggressivität", "MHX", "Heuristikprofil: monitor, guarded, sovereign oder custom (eigene Schwellwerte).", RiskHigh, "guarded", aggr, levels),
		newBool("mhx.autoTerminate", "Automatische Prozessbeendigung", "MHX", "Identitätsgeprüfte Prozessbeendigung bei bestätigter Detektion aktivieren.", RiskHigh, true, responseLevels),
		newInt("mhx.minimumConfidence", "Mindestkonfidenz", "MHX", "Mindestkonfidenz in Prozent, bevor eine Antwort ausgelöst wird.", RiskMedium, 60, 0, 100, "%", levels),
		newInt("mhx.analysisWindowSeconds", "Analysefenster", "MHX", "Zeitfenster für Prozess- und Netzwerk-Korrelation.", RiskMedium, 120, 30, 3600, "s", levels),
		newInt("mhx.terminationSeverityThreshold", "Beendigungs-Schweregrad", "MHX", "Ab welchem Schweregrad (1=LOW bis 4=CRITICAL) eine Beendigung erlaubt ist.", RiskHigh, 3, 1, 4, "Stufe", responseLevels),
		newBool("mhx.notificationsEnabled", "MHX-Benachrichtigungen", "MHX", "Detektionen und Antwortaktionen als Benachrichtigung melden.", RiskLow, true, levels),
		newEnum("mhx.applicationControl", "Anwendungssteuerung", "MHX", "WDAC/Anwendungskontrolle: off, audit oder enforce.", RiskHigh, "audit", []string{"off", "audit", "enforce"}, responseLevels),
		newBool("mhx.networkDefaultDeny", "Netzwerk-Default-Deny", "MHX", "Ausgehende Verbindungen standardmäßig blockieren, nur freigegebene Anwendungen erlauben.", RiskHigh, false, responseLevels),
		restricted,
	}
	return controls
}

func kineticControls() []Control {
	levels := allLevelIDs
	responseLevels := responseLevelIDs
	disarm := newInt("kinetic.autoDisarmSeconds", "Automatische Deaktivierung", "KINETIC", "Sekunden bis zur automatischen Deaktivierung. 0 deaktiviert die Automatik; aktive Werte liegen zwischen 300 und 604800.", RiskLow, 0, 0, 604800, "s", levels)
	disarm.custom = normalizeAutoDisarm
	return []Control{
		newBool("kinetic.persistedArmed", "Persistierte Bereitschaft", "KINETIC", "Kinetic nach einem Neustart erneut scharfschalten, sobald die verifizierten WFP/Threat-IP-Anforderungen erfüllt sind.", RiskHigh, false, responseLevels),
		newInt("kinetic.burstWindowSeconds", "Burst-Fenster", "KINETIC", "Aggregationsfenster für blockierte eingehende Verbindungen.", RiskMedium, 10, 2, 300, "s", levels),
		newInt("kinetic.minEvents", "Mindest-Ereignisse", "KINETIC", "Mindestanzahl blockierter Ereignisse für einen Burst-Kandidaten.", RiskMedium, 12, 3, 32, "Ereignisse", levels),
		newInt("kinetic.minDistinctPorts", "Mindest-Portvielfalt", "KINETIC", "Mindestanzahl unterschiedlicher Zielports für einen Burst-Kandidaten.", RiskMedium, 3, 2, 16, "Ports", levels),
		disarm,
		newBool("kinetic.notificationsEnabled", "Kinetic-Benachrichtigungen", "KINETIC", "Burst-Kandidaten und Bereitschaftsänderungen melden.", RiskLow, true, levels),
	}
}

func threatIntelligenceControls() []Control {
	levels := allLevelIDs
	// Default feed actions mirror the shipped threat-intelligence catalog:
	// four blocking feeds, four correlation feeds and one annotation feed.
	feedTokens := []string{
		"feodo:block", "spamhaus_drop_v4:block", "spamhaus_drop_v6:block",
		"cins_army:correlate", "blocklist_de:correlate", "emerging_threats:correlate",
		"ipsum:correlate", "firehol_l1:block", "tor_exit:annotate",
	}
	feedActions := newStringList("threatIntelligence.feedActions", "Feed-Aktionen", "THREAT INTELLIGENCE", "Aktion pro Feed (block, correlate, annotate), Format 'feed:aktion'. Blockierende Feed-Aktionen dürfen auf Guarded/Sovereign nicht unter block fallen.", RiskCritical, feedTokens, len(threatFeedIDs), 64, levels)
	feedActions.custom = normalizeFeedActions
	networks := newStringList("threatIntelligence.protectedNetworks", "Geschützte Netze", "THREAT INTELLIGENCE", "Öffentliche Unicast-Präfixe, die trotz Threat-Intelligence-Treffer geschützt bleiben.", RiskHigh, []string{}, 256, 49, levels)
	networks.custom = normalizeProtectedNetworks
	return []Control{
		newInt("threatIntelligence.pollIntervalSeconds", "Abrufintervall", "THREAT INTELLIGENCE", "Automatisches Synchronisationsintervall für Threat-Intelligence-Feeds.", RiskMedium, 43200, 900, 604800, "s", levels),
		newBool("threatIntelligence.autoSync", "Automatische Synchronisation", "THREAT INTELLIGENCE", "Feeds automatisch im konfigurierten Intervall aktualisieren.", RiskMedium, true, levels),
		newBool("threatIntelligence.blockingEnabled", "Blockierende Durchsetzung", "THREAT INTELLIGENCE", "Blockierende Feed-Indikatoren in die verifizierte WFP-Generation aufnehmen.", RiskCritical, true, levels),
		feedActions,
		networks,
		newBool("threatIntelligence.notifyOnSyncFailure", "Bei Sync-Fehler benachrichtigen", "THREAT INTELLIGENCE", "Fehlgeschlagene Feed-Synchronisationen im Benachrichtigungsfeed melden.", RiskLow, true, levels),
	}
}

func startupControls() []Control {
	levels := allLevelIDs
	return []Control{
		newBool("startup.autoStartService", "Dienst automatisch starten", "START", "GeDefense-Dienst beim Systemstart automatisch starten.", RiskMedium, true, levels),
		newBool("startup.launchTrayOnLogin", "Tray beim Anmelden starten", "START", "Systemtray-Anwendung beim Benutzer-Login starten.", RiskLow, true, levels),
		newBool("startup.readinessCheck", "Bereitschaftsprüfung", "START", "Nach Installation, Update oder Neustart die Bereitschaftsprüfung anzeigen.", RiskLow, true, levels),
		newInt("startup.healthRefreshSeconds", "Health-Refresh", "START", "Intervall für den stillen Hintergrund-Health-Refresh der Oberfläche.", RiskLow, 30, 10, 300, "s", levels),
		newBool("startup.applyHardeningOnStart", "Härtung beim Start anwenden", "START", "Gespeicherte Härtungs-Konfiguration beim Dienststart erneut anwenden.", RiskMedium, false, levels),
	}
}

func notificationControls() []Control {
	levels := allLevelIDs
	return []Control{
		newBool("notifications.enabled", "Benachrichtigungen aktiv", "BENACHRICHTIGUNGEN", "Benachrichtigungscenter und Systemmeldungen aktivieren.", RiskLow, true, levels),
		newBool("notifications.blockingEvents", "Blockereignisse", "BENACHRICHTIGUNGEN", "Blockierte Prozesse, Netzwerkverbindungen und Firewall-Ereignisse melden.", RiskLow, true, levels),
		newBool("notifications.startupSummary", "Startzusammenfassung", "BENACHRICHTIGUNGEN", "Nach dem Start eine Zusammenfassung des Schutzstatus anzeigen.", RiskLow, true, levels),
		newBool("notifications.soundAlerts", "Tonalarm", "BENACHRICHTIGUNGEN", "Zusätzlich einen dezenten Ton bei kritischen Ereignissen abspielen.", RiskLow, false, levels),
		newEnum("notifications.verbosity", "Detailtiefe", "BENACHRICHTIGUNGEN", "Detailgrad der Benachrichtigungen: minimal, normal oder detailed.", RiskLow, "normal", []string{"minimal", "normal", "detailed"}, levels),
		newInt("notifications.retentionDays", "Aufbewahrung", "BENACHRICHTIGUNGEN", "Aufbewahrungsdauer des Benachrichtigungsfeeds.", RiskLow, 14, 1, 90, "Tage", levels),
	}
}

// hardeningComponentIDs is the stable whitelist of hardening components. It
// mirrors the component IDs published by internal/hardening.
var hardeningComponentIDs = []string{
	"DefenderCloud", "ASR", "ControlledFolderAccess", "Firewall",
	"CredentialGuard", "MemoryIntegrity", "LSASS", "SMB",
	"PowerShellLogging", "UAC", "USBStorage", "RemoteDesktop",
}

// threatFeedIDs is the stable whitelist of threat-intelligence feed keys. It
// mirrors internal/threatintel's catalog keys.
var threatFeedIDs = []string{
	"feodo", "spamhaus_drop_v4", "spamhaus_drop_v6", "cins_army",
	"blocklist_de", "emerging_threats", "ipsum", "firehol_l1", "tor_exit",
}

var threatFeedBlockingIDs = []string{"feodo", "spamhaus_drop_v4", "spamhaus_drop_v6", "firehol_l1"}

// cloudBlockLevelRank maps the enum to a monotonic protection rank.
var cloudBlockLevelRank = map[string]int{
	"default": 0, "moderate": 1, "high": 2, "highPlus": 3, "zeroTolerance": 4,
}

var aggressivenessRank = map[string]int{
	LevelMonitor: 0, LevelGuarded: 1, LevelSovereign: 2,
}

// splitControlID splits the canonical "section.field" identifier.
func splitControlID(id string) (string, string) {
	for index := 0; index < len(id); index++ {
		if id[index] == '.' {
			return id[:index], id[index+1:]
		}
	}
	return "", ""
}

func shortControlID(id string) string {
	_, short := splitControlID(id)
	if short == "" {
		return id
	}
	return short
}

func levelConfirmation(level string) string {
	switch level {
	case LevelMonitor:
		return ConfirmationMonitor
	case LevelGuarded:
		return ConfirmationGuarded
	case LevelSovereign:
		return ConfirmationSovereign
	case LevelCustom:
		return ConfirmationCustom
	default:
		return ""
	}
}
