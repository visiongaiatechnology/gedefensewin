// STATUS: DIAMANT VGT SUPREME
package mhx

import (
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
	TimestampUTC   time.Time         `json:"timestampUtc"`
	CreationUTC    time.Time         `json:"creationUtc"`
	PID            uint32            `json:"pid"`
	ParentPID      uint32            `json:"parentPid"`
	Image          string            `json:"image"`
	ImagePath      string            `json:"imagePath"`
	CommandLine    string            `json:"commandLine"`
	SignerStatus   string            `json:"signerStatus"`
	SignerSubject  string            `json:"signerSubject"`
	SHA256         string            `json:"sha256"`
	ParentImage    string            `json:"parentImage"`
	ParentPath     string            `json:"parentPath"`
	ParentSigner   string            `json:"parentSigner"`
	ParentSigState string            `json:"parentSignerStatus"`
	ParentSHA256   string            `json:"parentSha256"`
	Ancestry       []ProcessIdentity `json:"ancestry"`
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

type Status struct {
	Engine                string                  `json:"engine"`
	Realtime              bool                    `json:"realtime"`
	Telemetry             string                  `json:"telemetry"`
	TelemetryHeartbeatUTC time.Time               `json:"telemetryHeartbeatUtc"`
	Enforcement           string                  `json:"enforcement"`
	DefenderBridge        string                  `json:"defenderBridge"`
	AppControl            string                  `json:"appControl"`
	KernelEnforcement     bool                    `json:"kernelEnforcement"`
	ProtectionMode        string                  `json:"protectionMode"`
	ProtectionHealth      string                  `json:"protectionHealth"`
	ProtectionVerifiedUTC time.Time               `json:"protectionVerifiedUtc,omitempty"`
	EventsEvaluated       uint64                  `json:"eventsEvaluated"`
	EventsBlocked         uint64                  `json:"eventsBlocked"`
	KnownBenign           uint64                  `json:"knownBenign"`
	ThreatIntelligence    threatintel.Status      `json:"threatIntelligence"`
	ThreatEnforcement     ThreatEnforcementStatus `json:"threatEnforcement"`
	NetworkTelemetry      string                  `json:"networkTelemetry"`
	NetworkConnections    uint64                  `json:"networkConnections"`
	WFPBlockTelemetry     string                  `json:"wfpBlockTelemetry"`
	WFPBlockedEvents      uint64                  `json:"wfpBlockedEvents"`
	ThreatNetworkHits     uint64                  `json:"threatNetworkHits"`
	AttackStories         uint64                  `json:"attackStories"`
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
