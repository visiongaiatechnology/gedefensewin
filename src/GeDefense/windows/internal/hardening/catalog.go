// STATUS: DIAMANT VGT SUPREME
package hardening

// ConfigField describes one settings field that the UI may render and that the
// validated apply path accepts. Type is one of "enum", "boolean", "integer",
// "array" or "uuid". ItemFields describes array entries. Values lists the
// accepted enum strings (or the accepted component IDs for the components
// array). Minimum/Maximum bound integer fields when non-zero.
type ConfigField struct {
	Key         string        `json:"key"`
	Label       string        `json:"label"`
	Type        string        `json:"type"`
	Description string        `json:"description"`
	Values      []string      `json:"values,omitempty"`
	Minimum     int           `json:"minimum,omitempty"`
	Maximum     int           `json:"maximum,omitempty"`
	ItemFields  []ConfigField `json:"itemFields,omitempty"`
}

// ComponentDefinition is stable hardening catalog metadata. It is available
// without running an audit so the UI can render every hardening tile before
// measured ComponentStatus values arrive.
type ComponentDefinition struct {
	ID                 string        `json:"id"`
	Label              string        `json:"label"`
	Category           string        `json:"category"`
	Description        string        `json:"description"`
	RebootRequired     bool          `json:"rebootRequired"`
	SupportedModes     []string      `json:"supportedModes"`
	ConfigurableFields []ConfigField `json:"configurableFields"`
}

// ASRRuleDefinition identifies one supported attack-surface-reduction rule.
type ASRRuleDefinition struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// SettingsGroup documents a validated hardening settings section for the UI.
type SettingsGroup struct {
	ID          string        `json:"id"`
	Label       string        `json:"label"`
	Description string        `json:"description"`
	Fields      []ConfigField `json:"fields"`
}

var supportedModes = []string{"Audit", "Enforce", "Component", "ApplyConfig"}

// asrRuleDefinitions is the product-supported ASR rule set. D5 and engine/
// Modules/Vgt.Defender.psm1 must keep this list identical; a test enforces it.
var asrRuleDefinitions = []ASRRuleDefinition{
	{ID: "56a863a9-875e-4185-98a7-b882c64b5ce5", Label: "Block executable content from email client and webmail"},
	{ID: "d4f940ab-401b-4efc-aadc-ad5f3c50688a", Label: "Block all Office applications from creating child processes"},
	{ID: "3b576869-a4ec-4529-8536-b80a7769e899", Label: "Block Office applications from creating executable content"},
	{ID: "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", Label: "Block Office applications from injecting code into other processes"},
	{ID: "d3e037e1-3eb8-44c8-a917-57927947596d", Label: "Block JavaScript or VBScript from launching downloaded executable content"},
	{ID: "5beb7efe-fd9a-4556-801d-275e5ffc04cc", Label: "Block execution of potentially obfuscated scripts"},
	{ID: "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", Label: "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"},
	{ID: "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", Label: "Block untrusted and unsigned processes that run from USB"},
	{ID: "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", Label: "Block credential stealing from the Windows local security authority subsystem"},
	{ID: "c1db55ab-c21a-4637-bb3f-a12568109d35", Label: "Block persistence through WMI event subscription"},
	{ID: "33ddedf1-c6e0-47cb-833e-de6133960387", Label: "Block process creations originating from PSExec and WMI commands"},
}

// componentDefinitions is the single source of truth for the hardening catalog.
// componentsFromResult derives measured ComponentStatus values from it.
var componentDefinitions = []ComponentDefinition{
	{
		ID: "DefenderCloud", Label: "Defender Cloud & Network", Category: "DEFENDER",
		Description:    "Cloudbasierter Blockschutz, PUA, sichere Samples und Netzwerkinspektion.",
		SupportedModes: supportedModes,
		ConfigurableFields: []ConfigField{
			enumConfigField("defender.cloudBlockLevel", "Cloud-Block-Level", "Aggressivität der cloudbasierten Blockentscheidung.", "Default", "Normal", "High", "HighPlus", "ZeroTolerance"),
			enumConfigField("defender.mapsReporting", "Cloud-Schutz (MAPS)", "Mitgliedschaft in Microsoft Advanced Protection Service.", "Disabled", "Basic", "Advanced"),
			enumConfigField("defender.submitSamplesConsent", "Sample-Übermittlung", "Zustimmung zur Übermittlung verdächtiger Dateien.", "AlwaysPrompt", "SendSafeSamples", "NeverSend", "SendAllSamples"),
			enumConfigField("defender.networkProtection", "Netzwerkschutz", "Blockiert schädliche Verbindungen auf Basis der Defender-Intelligenz.", "Enabled", "AuditMode", "Disabled"),
			enumConfigField("defender.puaProtection", "PUA-Schutz", "Blockiert potenziell unerwünschte Anwendungen.", "Enabled", "AuditMode", "Disabled"),
		},
	},
	{
		ID: "ASR", Label: "Attack Surface Reduction", Category: "DEFENDER",
		Description:    "Elf priorisierte ASR-Regeln; die Aktion ist je Regel konfigurierbar.",
		SupportedModes: supportedModes,
		ConfigurableFields: []ConfigField{{
			Key:         "defender.asrRules",
			Label:       "ASR-Regelaktionen",
			Type:        "array",
			Description: "Aktion pro unterstützter ASR-Regel. Nicht angegebene Regeln bleiben unverändert.",
			ItemFields: []ConfigField{
				{Key: "id", Label: "Regel-ID", Type: "uuid", Description: "Unterstützte ASR-Regel-ID."},
				enumConfigField("action", "Aktion", "Durchsetzungsmodus der Regel.", "Enabled", "AuditMode", "Disabled", "Warn"),
			},
		}},
	},
	{
		ID: "ControlledFolderAccess", Label: "Controlled Folder Access", Category: "RANSOMWARE",
		Description:    "Schreibzugriffe auf geschützte Ordner werden durch Defender kontrolliert.",
		SupportedModes: supportedModes,
		ConfigurableFields: []ConfigField{
			enumConfigField("defender.controlledFolderAccess", "Controlled Folder Access", "Block- oder Auditmodus für geschützte Ordner.", "Enabled", "AuditMode", "Disabled"),
		},
	},
	{
		ID: "Firewall", Label: "Windows Firewall", Category: "NETZWERK",
		Description:    "Alle Profile aktiv; eingehende Verbindungen standardmäßig blockiert.",
		SupportedModes: supportedModes,
		ConfigurableFields: []ConfigField{{
			Key:         "firewall.profiles",
			Label:       "Firewall-Profile",
			Type:        "array",
			Description: "Pro Profil nur die ausdrücklich angegebenen Einstellungen ändern.",
			ItemFields: []ConfigField{
				enumConfigField("name", "Profil", "Windows-Firewall-Profil.", "Domain", "Private", "Public"),
				{Key: "enabled", Label: "Aktiv", Type: "boolean", Description: "Profil aktivieren oder deaktivieren."},
				enumConfigField("defaultInboundAction", "Eingehend", "Standardaktion für eingehende Verbindungen.", "Block", "Allow"),
				enumConfigField("defaultOutboundAction", "Ausgehend", "Standardaktion für ausgehende Verbindungen.", "Allow", "Block"),
				{Key: "notifyOnListen", Label: "Benachrichtigung", Type: "boolean", Description: "Benachrichtigung bei blockiertem Listen."},
				{Key: "allowUnicastResponseToMulticast", Label: "Multicast-Antworten", Type: "boolean", Description: "Unicast-Antworten auf Multicast zulassen."},
				{Key: "logBlocked", Label: "Blockierte Pakete protokollieren", Type: "boolean", Description: "Blockierte Verbindungen ins Firewall-Log schreiben."},
				{Key: "logAllowed", Label: "Erlaubte Pakete protokollieren", Type: "boolean", Description: "Erlaubte Verbindungen ins Firewall-Log schreiben."},
				{Key: "logMaxSizeKilobytes", Label: "Log-Größe (KiB)", Type: "integer", Description: "Maximale Firewall-Log-Größe.", Minimum: 1, Maximum: 32767},
			},
		}},
	},
	{
		ID: "CredentialGuard", Label: "Credential Guard", Category: "ISOLATION",
		Description:    "Anmeldegeheimnisse werden in VBS-isolierter Umgebung geschützt.",
		RebootRequired: true, SupportedModes: supportedModes,
	},
	{
		ID: "MemoryIntegrity", Label: "Memory Integrity / HVCI", Category: "KERNEL",
		Description:    "Hypervisor-gestützte Codeintegrität und Microsoft-Treiberblockliste.",
		RebootRequired: true, SupportedModes: supportedModes,
	},
	{
		ID: "LSASS", Label: "LSASS Protected Process", Category: "IDENTITÄT",
		Description:    "LSASS läuft als geschützter Prozess; WDigest-Credentials bleiben deaktiviert.",
		RebootRequired: true, SupportedModes: supportedModes,
	},
	{
		ID: "SMB", Label: "SMB-Härtung", Category: "NETZWERK",
		Description:    "SMB1 deaktiviert und Signierung für Client und Server erzwungen.",
		RebootRequired: true, SupportedModes: supportedModes,
	},
	{
		ID: "PowerShellLogging", Label: "PowerShell & Process Audit", Category: "TELEMETRIE",
		Description:    "ScriptBlock-, Modul- und Prozessbefehlszeilen-Protokollierung.",
		SupportedModes: supportedModes,
	},
	{
		ID: "UAC", Label: "UAC Secure Desktop", Category: "IDENTITÄT",
		Description:    "Admin-Zustimmung und Secure Desktop sind erzwungen.",
		SupportedModes: supportedModes,
	},
	{
		ID: "USBStorage", Label: "USB-Massenspeicher sperren", Category: "ISOLATION",
		Description:    "USBSTOR wird vollständig deaktiviert.",
		SupportedModes: supportedModes,
	},
	{
		ID: "RemoteDesktop", Label: "Remote Desktop deaktivieren", Category: "NETZWERK",
		Description:    "Eingehende RDP-Sitzungen werden blockiert.",
		SupportedModes: supportedModes,
	},
}

func enumConfigField(key, label, description string, values ...string) ConfigField {
	return ConfigField{Key: key, Label: label, Type: "enum", Description: description, Values: values}
}

// Catalog returns a copy of the stable hardening component catalog. It requires
// no audit run, elevation or external command.
func Catalog() []ComponentDefinition {
	catalog := make([]ComponentDefinition, len(componentDefinitions))
	copy(catalog, componentDefinitions)
	for index := range catalog {
		catalog[index].SupportedModes = append([]string(nil), componentDefinitions[index].SupportedModes...)
		if fields := componentDefinitions[index].ConfigurableFields; len(fields) > 0 {
			catalog[index].ConfigurableFields = cloneConfigFields(fields)
		} else {
			catalog[index].ConfigurableFields = []ConfigField{}
		}
	}
	return catalog
}

// Catalog returns the static component catalog through the engine handle so
// callers that already hold the hardening engine can expose it through the same
// dependency they use for measured status.
func (e *Engine) Catalog() []ComponentDefinition { return Catalog() }

// ASRRuleCatalog returns a copy of the supported ASR rule identifiers.
func ASRRuleCatalog() []ASRRuleDefinition {
	rules := make([]ASRRuleDefinition, len(asrRuleDefinitions))
	copy(rules, asrRuleDefinitions)
	return rules
}

// SettingsCatalog documents the validated settings sections accepted by
// ApplySettings so the UI can render the configuration surface without probing.
func SettingsCatalog() []SettingsGroup {
	groups := []SettingsGroup{
		{
			ID:          "defender",
			Label:       "Microsoft Defender",
			Description: "Defender-Einstellungen, ASR-Regelaktionen und Cloud-Schutz. Jedes Feld wird vor dem Anwenden validiert.",
			Fields: []ConfigField{
				enumConfigField("cloudBlockLevel", "Cloud-Block-Level", "Aggressivität der cloudbasierten Blockentscheidung.", "Default", "Normal", "High", "HighPlus", "ZeroTolerance"),
				enumConfigField("mapsReporting", "Cloud-Schutz (MAPS)", "Mitgliedschaft in Microsoft Advanced Protection Service.", "Disabled", "Basic", "Advanced"),
				enumConfigField("submitSamplesConsent", "Sample-Übermittlung", "Zustimmung zur Übermittlung verdächtiger Dateien.", "AlwaysPrompt", "SendSafeSamples", "NeverSend", "SendAllSamples"),
				enumConfigField("networkProtection", "Netzwerkschutz", "Blockiert schädliche Verbindungen.", "Enabled", "AuditMode", "Disabled"),
				enumConfigField("puaProtection", "PUA-Schutz", "Blockiert potenziell unerwünschte Anwendungen.", "Enabled", "AuditMode", "Disabled"),
				enumConfigField("controlledFolderAccess", "Controlled Folder Access", "Block- oder Auditmodus für geschützte Ordner.", "Enabled", "AuditMode", "Disabled"),
				{
					Key: "asrRules", Label: "ASR-Regelaktionen", Type: "array",
					Description: "Aktion pro unterstützter ASR-Regel.",
					ItemFields: []ConfigField{
						{Key: "id", Label: "Regel-ID", Type: "uuid", Description: "Unterstützte ASR-Regel-ID.", Values: asrRuleIDs()},
						enumConfigField("action", "Aktion", "Durchsetzungsmodus der Regel.", "Enabled", "AuditMode", "Disabled", "Warn"),
					},
				},
			},
		},
		{
			ID:          "firewall",
			Label:       "Windows Firewall",
			Description: "Pro Profil werden nur ausdrücklich angegebene Einstellungen geändert.",
			Fields: []ConfigField{{
				Key: "profiles", Label: "Firewall-Profile", Type: "array",
				Description: "Bis zu drei Profile (Domain, Private, Public).",
				ItemFields:  cloneConfigFields(componentDefinitions[3].ConfigurableFields[0].ItemFields),
			}},
		},
		{
			ID:          "components",
			Label:       "Härtungskomponenten",
			Description: "Unterstützte Komponenten zusätzlich zur Profil- oder Einzelhärtung anwenden.",
			Fields: []ConfigField{{
				Key: "components", Label: "Komponenten", Type: "array",
				Description: "IDs aus dem Härtungskatalog.",
				Values:      componentIDs(),
			}},
		},
	}
	return groups
}

func componentIDs() []string {
	ids := make([]string, 0, len(componentDefinitions))
	for _, definition := range componentDefinitions {
		ids = append(ids, definition.ID)
	}
	return ids
}

func asrRuleIDs() []string {
	ids := make([]string, 0, len(asrRuleDefinitions))
	for _, rule := range asrRuleDefinitions {
		ids = append(ids, rule.ID)
	}
	return ids
}

func cloneConfigFields(fields []ConfigField) []ConfigField {
	cloned := make([]ConfigField, len(fields))
	for index, field := range fields {
		cloned[index] = field
		cloned[index].Values = append([]string(nil), field.Values...)
		cloned[index].ItemFields = cloneConfigFields(field.ItemFields)
	}
	return cloned
}

// componentsFromResult derives the measured component status list from an
// audited Result. The IDs, labels, categories, order and Active semantics are
// preserved from the previous V4 schema.
func componentsFromResult(result Result) []ComponentStatus {
	return []ComponentStatus{
		{ID: "DefenderCloud", Name: "Defender Cloud & Network", Category: "DEFENDER", Active: result.CloudProtection && result.NetworkProtection && result.RealTimeProtection, Description: "Cloudbasierter Blockschutz, PUA, sichere Samples und Netzwerkinspektion."},
		{ID: "ASR", Name: "Attack Surface Reduction", Category: "DEFENDER", Active: result.ASRRules >= 11 && result.ASRBlockRules >= 11, Description: "Elf priorisierte ASR-Regeln; die Aktion ist je Regel konfigurierbar."},
		{ID: "ControlledFolderAccess", Name: "Controlled Folder Access", Category: "RANSOMWARE", Active: result.ControlledFolderAccess, Description: "Schreibzugriffe auf geschützte Ordner werden durch Defender kontrolliert."},
		{ID: "Firewall", Name: "Windows Firewall", Category: "NETZWERK", Active: result.Firewall, Description: "Alle Profile aktiv; eingehende Verbindungen standardmäßig blockiert."},
		{ID: "CredentialGuard", Name: "Credential Guard", Category: "ISOLATION", Active: result.CredentialGuard, RebootRequired: !result.CredentialGuard, Description: "Anmeldegeheimnisse werden in VBS-isolierter Umgebung geschützt."},
		{ID: "MemoryIntegrity", Name: "Memory Integrity / HVCI", Category: "KERNEL", Active: result.MemoryIntegrity && result.VulnerableDriverBlocklist, RebootRequired: !result.MemoryIntegrity, Description: "Hypervisor-gestützte Codeintegrität und Microsoft-Treiberblockliste."},
		{ID: "LSASS", Name: "LSASS Protected Process", Category: "IDENTITÄT", Active: result.LSAProtection, RebootRequired: !result.LSAProtection, Description: "LSASS läuft als geschützter Prozess; WDigest-Credentials bleiben deaktiviert."},
		{ID: "SMB", Name: "SMB-Härtung", Category: "NETZWERK", Active: result.SMBHardening, RebootRequired: !result.SMBHardening, Description: "SMB1 deaktiviert und Signierung für Client und Server erzwungen."},
		{ID: "PowerShellLogging", Name: "PowerShell & Process Audit", Category: "TELEMETRIE", Active: result.PowerShellLogging, Description: "ScriptBlock-, Modul- und Prozessbefehlszeilen-Protokollierung."},
		{ID: "UAC", Name: "UAC Secure Desktop", Category: "IDENTITÄT", Active: result.UACSecureDesktop, Description: "Admin-Zustimmung und Secure Desktop sind erzwungen."},
		{ID: "USBStorage", Name: "USB-Massenspeicher sperren", Category: "ISOLATION", Active: result.USBStorageBlocked, RebootRequired: false, Description: "USBSTOR wird vollständig deaktiviert."},
		{ID: "RemoteDesktop", Name: "Remote Desktop deaktivieren", Category: "NETZWERK", Active: result.RemoteDesktopDisabled, Description: "Eingehende RDP-Sitzungen werden blockiert."},
	}
}
