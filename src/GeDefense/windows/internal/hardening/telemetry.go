// STATUS: DIAMANT VGT SUPREME
package hardening

// DefenderTelemetry is a read-only snapshot of the local Microsoft Defender,
// attack-surface-reduction and Windows Firewall policy state. Every value is
// either measured from the Windows APIs named in SourcesAttempted or explicitly
// reported as unavailable: nullable scalars stay null and the matching
// availability flag is false. Values are never synthesized from defaults.
//
// The JSON keys are the exact keys emitted by engine/Modules/Vgt.Defender.psm1
// and engine/Modules/Vgt.System.psm1. The schema is additive: older PowerShell
// payloads that do not emit DefenderTelemetry decode as a nil pointer and the
// established Result fields stay authoritative for legacy clients.
type DefenderTelemetry struct {
	CapturedUTC              string            `json:"CapturedUtc"`
	SourcesAttempted         []string          `json:"SourcesAttempted"`
	Available                bool              `json:"Available"`
	ComputerStatusAvailable  bool              `json:"ComputerStatusAvailable"`
	PreferenceAvailable      bool              `json:"PreferenceAvailable"`
	ThreatDetectionAvailable bool              `json:"ThreatDetectionAvailable"`
	ThreatQueryAvailable     bool              `json:"ThreatQueryAvailable"`
	FirewallAvailable        bool              `json:"FirewallAvailable"`
	Status                   *DefenderStatus   `json:"Status"`
	Preference               *DefenderPrefs    `json:"Preference"`
	AttackSurfaceReduction   *ASRTelemetry     `json:"AttackSurfaceReduction"`
	Exclusions               *ExclusionsReport `json:"Exclusions"`
	Threats                  *ThreatReport     `json:"Threats"`
	Firewall                 *FirewallReport   `json:"Firewall"`
}

// DefenderStatus mirrors the measured Get-MpComputerStatus values. A nil field
// means the property could not be read on this host, not that it is false.
type DefenderStatus struct {
	AntivirusEnabled               *bool   `json:"AntivirusEnabled"`
	AntispywareEnabled             *bool   `json:"AntispywareEnabled"`
	AMServiceEnabled               *bool   `json:"AMServiceEnabled"`
	RealTimeProtectionEnabled      *bool   `json:"RealTimeProtectionEnabled"`
	BehaviorMonitorEnabled         *bool   `json:"BehaviorMonitorEnabled"`
	IoavProtectionEnabled          *bool   `json:"IoavProtectionEnabled"`
	OnAccessProtectionEnabled      *bool   `json:"OnAccessProtectionEnabled"`
	IsTamperProtected              *bool   `json:"IsTamperProtected"`
	NISEnabled                     *bool   `json:"NISEnabled"`
	DefenderSignaturesOutOfDate    *bool   `json:"DefenderSignaturesOutOfDate"`
	AntivirusSignatureVersion      *string `json:"AntivirusSignatureVersion"`
	AntivirusSignatureAge          *int    `json:"AntivirusSignatureAge"`
	AntivirusSignatureLastUpdated  *string `json:"AntivirusSignatureLastUpdated"`
	AntispywareSignatureVersion    *string `json:"AntispywareSignatureVersion"`
	AntispywareSignatureAge        *int    `json:"AntispywareSignatureAge"`
	AntispywareSignatureLastUpdate *string `json:"AntispywareSignatureLastUpdated"`
	NISSignatureVersion            *string `json:"NISSignatureVersion"`
	NISSignatureAge                *int    `json:"NISSignatureAge"`
	AMEngineVersion                *string `json:"AMEngineVersion"`
	AMProductVersion               *string `json:"AMProductVersion"`
	QuickScanAge                   *int    `json:"QuickScanAge"`
	FullScanAge                    *int    `json:"FullScanAge"`
}

// DefenderPrefs mirrors the measured Get-MpPreference values that this product
// supports configuring. Raw numeric enum values are exposed next to the
// canonical name so a UI never has to guess an unknown future enum value.
type DefenderPrefs struct {
	CloudBlockLevel                                *string `json:"CloudBlockLevel"`
	CloudBlockLevelRaw                             *int    `json:"CloudBlockLevelRaw"`
	MAPSReporting                                  *string `json:"MAPSReporting"`
	MAPSReportingRaw                               *int    `json:"MAPSReportingRaw"`
	SubmitSamplesConsent                           *string `json:"SubmitSamplesConsent"`
	SubmitSamplesConsentRaw                        *int    `json:"SubmitSamplesConsentRaw"`
	PUAProtection                                  *string `json:"PUAProtection"`
	PUAProtectionRaw                               *int    `json:"PUAProtectionRaw"`
	NetworkProtection                              *string `json:"NetworkProtection"`
	NetworkProtectionRaw                           *int    `json:"NetworkProtectionRaw"`
	ControlledFolderAccess                         *string `json:"ControlledFolderAccess"`
	ControlledFolderAccessRaw                      *int    `json:"ControlledFolderAccessRaw"`
	ControlledFolderAccessAllowedApplicationsCount *int    `json:"ControlledFolderAccessAllowedApplicationsCount"`
	ControlledFolderAccessProtectedFoldersCount    *int    `json:"ControlledFolderAccessProtectedFoldersCount"`
}

// ASRTelemetry reports the configured attack-surface-reduction rules. Rules
// that are not configured keep a nil Action/ActionName and Configured=false.
type ASRTelemetry struct {
	Available          bool           `json:"Available"`
	RulesTruncated     bool           `json:"RulesTruncated"`
	ConfiguredCount    int            `json:"ConfiguredCount"`
	EnabledCount       int            `json:"EnabledCount"`
	AuditCount         int            `json:"AuditCount"`
	WarnCount          int            `json:"WarnCount"`
	RecommendedCount   int            `json:"RecommendedCount"`
	RecommendedMissing []string       `json:"RecommendedMissing"`
	Rules              []ASRRuleState `json:"Rules"`
}

// ASRRuleState is the measured state of one ASR rule identifier.
type ASRRuleState struct {
	ID          string  `json:"Id"`
	Label       *string `json:"Label"`
	Recommended bool    `json:"Recommended"`
	Configured  bool    `json:"Configured"`
	Action      *int    `json:"Action"`
	ActionName  *string `json:"ActionName"`
}

// ExclusionsReport reports Defender exclusion inventory. Path, process and IP
// exclusions are only counted (they can contain user or system paths); only
// extension strings are exposed as values, sanitized and bounded. When the
// process token may not read exclusions, the affected counts stay nil.
type ExclusionsReport struct {
	Available           bool     `json:"Available"`
	PathCount           *int     `json:"PathCount"`
	ProcessCount        *int     `json:"ProcessCount"`
	ExtensionCount      *int     `json:"ExtensionCount"`
	IPAddressCount      *int     `json:"IpAddressCount"`
	Extensions          []string `json:"Extensions"`
	ExtensionsTruncated bool     `json:"ExtensionsTruncated"`
}

// ThreatReport reports the measured Defender threat detection inventory counts.
type ThreatReport struct {
	Available               bool    `json:"Available"`
	DetectionQueryAvailable bool    `json:"DetectionQueryAvailable"`
	ThreatQueryAvailable    bool    `json:"ThreatQueryAvailable"`
	DetectionCount          *int    `json:"DetectionCount"`
	ActiveThreatCount       *int    `json:"ActiveThreatCount"`
	LatestDetectionUTC      *string `json:"LatestDetectionUtc"`
}

// FirewallReport mirrors Get-NetFirewallProfile.
type FirewallReport struct {
	Available           bool              `json:"Available"`
	ProfileCount        int               `json:"ProfileCount"`
	EnabledProfileCount int               `json:"EnabledProfileCount"`
	Profiles            []FirewallProfile `json:"Profiles"`
}

// FirewallProfile is the measured state of one Windows Firewall profile.
type FirewallProfile struct {
	Name                            string  `json:"Name"`
	Enabled                         *bool   `json:"Enabled"`
	DefaultInboundAction            *string `json:"DefaultInboundAction"`
	DefaultOutboundAction           *string `json:"DefaultOutboundAction"`
	NotifyOnListen                  *bool   `json:"NotifyOnListen"`
	AllowUnicastResponseToMulticast *bool   `json:"AllowUnicastResponseToMulticast"`
	LogBlocked                      *bool   `json:"LogBlocked"`
	LogAllowed                      *bool   `json:"LogAllowed"`
	LogMaxSizeKilobytes             *int    `json:"LogMaxSizeKilobytes"`
}
