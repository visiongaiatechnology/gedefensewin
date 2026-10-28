// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
	"github.com/visiongaiatechnology/gedefense/windows/internal/traffic"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

type Severity string

const (
	SeverityInformational Severity = "INFORMATIONAL"
	SeverityLow           Severity = "LOW"
	SeverityMedium        Severity = "MEDIUM"
	SeverityHigh          Severity = "HIGH"
	SeverityCritical      Severity = "CRITICAL"
)

type Disposition string

const (
	DispositionAllow Disposition = "ALLOW"
	DispositionAudit Disposition = "AUDIT"
	DispositionBlock Disposition = "BLOCK"
)

type ProcessEvent struct {
	TimestampUTC  time.Time `json:"timestampUtc"`
	CreationUTC   time.Time `json:"creationUtc"`
	PID           uint32    `json:"pid"`
	ParentPID     uint32    `json:"parentPid"`
	Image         string    `json:"image"`
	ImagePath     string    `json:"imagePath"`
	CommandLine   string    `json:"commandLine"`
	SignerStatus  string    `json:"signerStatus"`
	SignerSubject string    `json:"signerSubject"`
	// OriginalImageName is the PE "OriginalFilename" version resource of the
	// image (best effort). It lets the process sensor detect renamed system
	// binaries without trusting the file name alone: a copy of
	// powershell.exe as updater.exe still carries OriginalFilename
	// "PowerShell.EXE". ImageVersionCompany is the PE CompanyName resource.
	OriginalImageName   string            `json:"originalImageName,omitempty"`
	ImageVersionCompany string            `json:"imageVersionCompany,omitempty"`
	SHA256              string            `json:"sha256"`
	ParentImage         string            `json:"parentImage"`
	ParentPath          string            `json:"parentPath"`
	ParentSigner        string            `json:"parentSigner"`
	ParentSigState      string            `json:"parentSignerStatus"`
	ParentSHA256        string            `json:"parentSha256"`
	Ancestry            []ProcessIdentity `json:"ancestry"`
}

type ProcessIdentity struct {
	PID          uint32 `json:"pid"`
	Image        string `json:"image"`
	Path         string `json:"path"`
	SignerStatus string `json:"signerStatus"`
	Signer       string `json:"signer"`
	SHA256       string `json:"sha256"`
}

type Analysis struct {
	ID                string      `json:"id"`
	TimestampUTC      time.Time   `json:"timestampUtc"`
	InitialSeverity   Severity    `json:"initialSeverity"`
	EffectiveSeverity Severity    `json:"effectiveSeverity"`
	Disposition       Disposition `json:"disposition"`
	Detection         string      `json:"detection"`
	Classification    string      `json:"classification"`
	Identified        string      `json:"identifiedComponent"`
	Purpose           string      `json:"purpose"`
	ConfidenceBasis   int         `json:"confidenceBasisPoints"`
	PID               uint32      `json:"pid"`
	CreationUTC       time.Time   `json:"creationUtc,omitempty"`
	ParentPID         uint32      `json:"parentPid"`
	Image             string      `json:"image"`
	Parent            string      `json:"parent"`
	Signer            string      `json:"signer"`
	DecodedEncoding   string      `json:"decodedEncoding,omitempty"`
	DecodedSHA256     string      `json:"decodedSha256,omitempty"`
	DecodedBytes      int         `json:"decodedBytes,omitempty"`
	Signals           []string    `json:"signals"`
	SignalCategories  []string    `json:"signalCategories"`
	ResponseAuthority bool        `json:"responseAuthority"`
}

type ProtectedNetworkPolicy = threatintel.ProtectedNetworkPolicy

type ThreatEnforcementStatus struct {
	State             string    `json:"state"`
	DesiredGeneration string    `json:"desiredGenerationSha256,omitempty"`
	ActiveGeneration  string    `json:"activeGenerationSha256,omitempty"`
	Indicators        int       `json:"indicators"`
	Rules             int       `json:"rules"`
	Shards            int       `json:"shards"`
	Mode              string    `json:"mode,omitempty"`
	CleanupPending    bool      `json:"cleanupPending"`
	VerifiedUTC       time.Time `json:"verifiedUtc,omitempty"`
	Error             string    `json:"error,omitempty"`
}

type KineticIncident struct {
	TimestampUTC     time.Time `json:"timestampUtc"`
	RemoteIP         string    `json:"remoteIp"`
	LocalPort        uint16    `json:"localPort"`
	ThreatMatched    bool      `json:"threatMatched"`
	ThreatSources    []string  `json:"threatSources,omitempty"`
	VerifiedWFPBlock bool      `json:"verifiedWfpBlock"`
	Classification   string    `json:"classification"`
}
type Status struct {
	KineticSources             []kinetic.Source        `json:"kineticSources"`
	KineticIncidents           []KineticIncident       `json:"kineticIncidents"`
	Traffic                    traffic.Sample          `json:"traffic"`
	KineticArmed               bool                    `json:"kineticArmed"`
	KineticThreatCorrelations  uint64                  `json:"kineticThreatCorrelations"`
	KineticBlockedCorrelations uint64                  `json:"kineticBlockedCorrelations"`
	Kinetic                    kinetic.Snapshot        `json:"kinetic"`
	KineticReadiness           kinetic.Readiness       `json:"kineticReadiness"`
	UncorrelatedThreatHits     uint64                  `json:"uncorrelatedThreatHits"`
	Engine                     string                  `json:"engine"`
	Realtime                   bool                    `json:"realtime"`
	Telemetry                  string                  `json:"telemetry"`
	TelemetryHeartbeatUTC      time.Time               `json:"telemetryHeartbeatUtc"`
	Enforcement                string                  `json:"enforcement"`
	DefenderBridge             string                  `json:"defenderBridge"`
	AppControl                 string                  `json:"appControl"`
	KernelEnforcement          bool                    `json:"kernelEnforcement"`
	ProtectionMode             string                  `json:"protectionMode"`
	ProtectionHealth           string                  `json:"protectionHealth"`
	ProtectionVerifiedUTC      time.Time               `json:"protectionVerifiedUtc,omitempty"`
	EventsEvaluated            uint64                  `json:"eventsEvaluated"`
	EventsBlocked              uint64                  `json:"eventsBlocked"`
	KnownBenign                uint64                  `json:"knownBenign"`
	ThreatIntelligence         threatintel.Status      `json:"threatIntelligence"`
	ThreatEnforcement          ThreatEnforcementStatus `json:"threatEnforcement"`
	NetworkTelemetry           string                  `json:"networkTelemetry"`
	NetworkConnections         uint64                  `json:"networkConnections"`
	WFPBlockTelemetry          string                  `json:"wfpBlockTelemetry"`
	WFPBlockedEvents           uint64                  `json:"wfpBlockedEvents"`
	ThreatNetworkHits          uint64                  `json:"threatNetworkHits"`
	AttackStories              uint64                  `json:"attackStories"`

	// V5 management projections. All values are derived from persisted,
	// verified runtime state; none of them are invented UI placeholders.
	KineticSettings    KineticSettingsSnapshot   `json:"kineticSettings"`
	PolicySettings     PolicySettings            `json:"policySettings"`
	ThreatIntelPolling threatintel.PollingConfig `json:"threatIntelPolling"`
	DefenderTelemetry  *DefenderTelemetry        `json:"defenderTelemetry,omitempty"`
	NotificationCount  int                       `json:"notificationCount"`
}

type NetworkFinding struct {
	ID               string             `json:"id"`
	TimestampUTC     time.Time          `json:"timestampUtc"`
	PID              uint32             `json:"pid"`
	Image            string             `json:"image,omitempty"`
	RemoteIP         string             `json:"remoteIp"`
	RemotePort       uint16             `json:"remotePort"`
	LocalPort        uint16             `json:"localPort"`
	ThreatIntel      bool               `json:"threatIntel"`
	ProtectedNetwork bool               `json:"protectedNetwork,omitempty"`
	ThreatAction     threatintel.Action `json:"threatAction,omitempty"`
	ThreatSources    []string           `json:"threatSources,omitempty"`
	Severity         Severity           `json:"severity"`
	CorrelationID    string             `json:"correlationId,omitempty"`
	Response         string             `json:"response"`
	FilterOrigin     string             `json:"filterOrigin,omitempty"`
}

type AttackStory struct {
	ID                string             `json:"id"`
	StartedUTC        time.Time          `json:"startedUtc"`
	UpdatedUTC        time.Time          `json:"updatedUtc"`
	PID               uint32             `json:"pid"`
	Image             string             `json:"image"`
	ProcessAnalysisID string             `json:"processAnalysisId,omitempty"`
	Severity          Severity           `json:"severity"`
	Signals           []string           `json:"signals"`
	ThreatAction      threatintel.Action `json:"threatAction,omitempty"`
	ProtectedNetwork  bool               `json:"protectedNetwork,omitempty"`
	ThreatSources     []string           `json:"threatSources,omitempty"`
	RemoteIP          string             `json:"remoteIp,omitempty"`
	RemotePort        uint16             `json:"remotePort,omitempty"`
	Response          string             `json:"response"`
}
