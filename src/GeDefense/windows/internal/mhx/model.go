// STATUS: DIAMANT VGT SUPREME
package mhx

import "time"

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
	ParentPID         uint32      `json:"parentPid"`
	Image             string      `json:"image"`
	Parent            string      `json:"parent"`
	Signer            string      `json:"signer"`
	DecodedEncoding   string      `json:"decodedEncoding,omitempty"`
	DecodedPayload    string      `json:"decodedPayload,omitempty"`
	Signals           []string    `json:"signals"`
}

type FeedStatus struct {
	LastAttemptUTC time.Time `json:"lastAttemptUtc"`
	LastSuccessUTC time.Time `json:"lastSuccessUtc"`
	NextSyncUTC    time.Time `json:"nextSyncUtc"`
	Indicators     int       `json:"indicators"`
	Generation     string    `json:"generationSha256"`
	State          string    `json:"state"`
	Error          string    `json:"error,omitempty"`
}

type Status struct {
	Engine                string     `json:"engine"`
	Realtime              bool       `json:"realtime"`
	Telemetry             string     `json:"telemetry"`
	TelemetryHeartbeatUTC time.Time  `json:"telemetryHeartbeatUtc"`
	Enforcement           string     `json:"enforcement"`
	DefenderBridge        string     `json:"defenderBridge"`
	AppControl            string     `json:"appControl"`
	KernelEnforcement     bool       `json:"kernelEnforcement"`
	ProtectionMode        string     `json:"protectionMode"`
	EventsEvaluated       uint64     `json:"eventsEvaluated"`
	EventsBlocked         uint64     `json:"eventsBlocked"`
	KnownBenign           uint64     `json:"knownBenign"`
	ThreatIntelligence    FeedStatus `json:"threatIntelligence"`
}
