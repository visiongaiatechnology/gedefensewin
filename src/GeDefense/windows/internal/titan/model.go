// STATUS: DIAMANT VGT SUPREME
package titan

import "time"

// TrustStatus is the only attribution Titan makes: whether an observed change
// matched the owner's authorization policy. It is never a claim about the
// identity or motive of an actor.
type TrustStatus string

const (
	TrustAuthorized  TrustStatus = "AUTHORIZED"
	TrustTolerated   TrustStatus = "TOLERATED"
	TrustUnexpected  TrustStatus = "UNEXPECTED"
	TrustCompromised TrustStatus = "COMPROMISED"
)

// EventType classifies a machine-observable change.
type EventType string

const (
	EventFileCreated        EventType = "FILE_CREATED"
	EventFileModified       EventType = "FILE_MODIFIED"
	EventFileDeleted        EventType = "FILE_DELETED"
	EventFileRenamed        EventType = "FILE_RENAMED"
	EventPersistenceAdded   EventType = "PERSISTENCE_ADDED"
	EventPersistenceChanged EventType = "PERSISTENCE_CHANGED"
	EventPersistenceRemoved EventType = "PERSISTENCE_REMOVED"
	EventSecurityChanged    EventType = "SECURITY_CONFIG_CHANGED"
	EventSecurityDowngrade  EventType = "SECURITY_DOWNGRADE"
	EventBootChanged        EventType = "BOOT_CONFIG_CHANGED"
	EventQuarantined        EventType = "OBJECT_QUARANTINED"
	EventRestored           EventType = "OBJECT_RESTORED"
	EventReviewed           EventType = "OBJECT_REVIEWED"
	EventSensorHealth       EventType = "SENSOR_HEALTH"
	EventSelfIntegrity      EventType = "TITAN_SELF_INTEGRITY"
)

// Severity is an operational priority, not an attribution.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// CorrelationQuality records how strongly an event's context is linked to the
// change. OBSERVED means directly evidenced by the collector; TEMPORAL means a
// bounded time correlation and must never be rendered as proof.
type CorrelationQuality string

const (
	CorrelationObserved CorrelationQuality = "OBSERVED"
	CorrelationTemporal CorrelationQuality = "TEMPORAL"
	CorrelationNone     CorrelationQuality = "NONE"
)

// ObjectKind identifies the changed object class.
type ObjectKind string

const (
	ObjectFile          ObjectKind = "FILE"
	ObjectRegistryValue ObjectKind = "REGISTRY_VALUE"
	ObjectRegistryKey   ObjectKind = "REGISTRY_KEY"
	ObjectService       ObjectKind = "SERVICE"
	ObjectScheduledTask ObjectKind = "SCHEDULED_TASK"
	ObjectBoot          ObjectKind = "BOOT"
	ObjectSensor        ObjectKind = "SENSOR"
	ObjectQuarantine    ObjectKind = "QUARANTINE_OBJECT"
)

// RiskClass is derived from the path or object being changed.
type RiskClass string

const (
	RiskUnknown     RiskClass = "UNKNOWN"
	RiskUserContent RiskClass = "USER_CONTENT"
	RiskIngress     RiskClass = "INGRESS"
	RiskPersistence RiskClass = "PERSISTENCE"
	RiskSecurity    RiskClass = "SECURITY_CONFIG"
	RiskSystem      RiskClass = "SYSTEM_COMPONENT"
	RiskBoot        RiskClass = "BOOT_TRUST"
	RiskTitan       RiskClass = "TITAN_SELF"
)

// Object is the changed entity. File bodies are never stored in the journal;
// only metadata and a SHA-256 are recorded.
type Object struct {
	Kind            ObjectKind `json:"kind"`
	Path            string     `json:"path,omitempty"`
	Name            string     `json:"name,omitempty"`
	SHA256          string     `json:"sha256,omitempty"`
	Size            int64      `json:"size,omitempty"`
	ModifiedUTC     time.Time  `json:"modifiedUtc,omitempty"`
	FileType        string     `json:"fileType,omitempty"`
	Change          string     `json:"change,omitempty"`
	SignatureStatus string     `json:"signatureStatus,omitempty"`
	ZoneIdentifier  string     `json:"zoneIdentifier,omitempty"`
}

// Actor is populated only from evidence Titan actually gathered. PID 0 and an
// empty image mean no actor was observed; the UI must say so.
type Actor struct {
	PID           uint32 `json:"pid,omitempty"`
	ParentPID     uint32 `json:"parentPid,omitempty"`
	Image         string `json:"image,omitempty"`
	Path          string `json:"path,omitempty"`
	User          string `json:"user,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	SignerSubject string `json:"signerSubject,omitempty"`
	// ProcessChain is the bounded observed ancestry, leaf first. It is evidence,
	// not invented file-to-process attribution: the sensor can only prove that
	// these processes existed in the same observation window.
	ProcessChain        []string           `json:"processChain,omitempty"`
	CorrelationQuality  CorrelationQuality `json:"correlationQuality"`
	CorrelationNote     string             `json:"correlationNote,omitempty"`
	ObservedProcessTime time.Time          `json:"observedProcessTime,omitempty"`
}

// NetworkContext is deliberately narrow. It never claims that a connection
// transferred a file; it reports only what was observed and how it was linked.
type NetworkContext struct {
	CorrelationQuality CorrelationQuality `json:"correlationQuality"`
	RemoteAddress      string             `json:"remoteAddress,omitempty"`
	RemotePort         uint16             `json:"remotePort,omitempty"`
	LocalPort          uint16             `json:"localPort,omitempty"`
	Image              string             `json:"image,omitempty"`
	Detail             string             `json:"detail,omitempty"`
}

// Authorization is the policy conclusion for one event.
type Authorization struct {
	Status         TrustStatus `json:"status"`
	RiskClass      RiskClass   `json:"riskClass"`
	PolicyMode     string      `json:"policyMode"`
	MatchedGrant   string      `json:"matchedGrant,omitempty"`
	Reason         string      `json:"reason"`
	RiskScore      int         `json:"riskScore"`
	NeedsReview    bool        `json:"needsReview"`
	AutoQuarantine bool        `json:"autoQuarantine"`
}

// Response records what Titan did, including partial or unavailable outcomes.
type Response struct {
	Action       string `json:"action"`
	State        string `json:"state"`
	Detail       string `json:"detail,omitempty"`
	QuarantineID string `json:"quarantineId,omitempty"`
	OriginalGone bool   `json:"originalGone,omitempty"`
}

// Collection records telemetry provenance and known gaps.
type Collection struct {
	Source           string `json:"source"`
	TelemetryHealth  string `json:"telemetryHealth"`
	ObservationError string `json:"observationError,omitempty"`
}

// Event is the append-only Titan record. Hash and PreviousHash form a
// tamper-evident chain; the checkpoint signer anchors the chain independently
// of the local journal.
type Event struct {
	Sequence      uint64         `json:"sequence"`
	ID            string         `json:"id"`
	BootID        string         `json:"bootId"`
	TimestampUTC  time.Time      `json:"timestampUtc"`
	TimeSource    string         `json:"timeSource"`
	Type          EventType      `json:"eventType"`
	Severity      Severity       `json:"severity"`
	Object        Object         `json:"object"`
	Actor         Actor          `json:"actor"`
	Network       NetworkContext `json:"network"`
	Authorization Authorization  `json:"authorization"`
	Response      Response       `json:"response"`
	Collection    Collection     `json:"collection"`
	PreviousHash  string         `json:"previousHash"`
	Hash          string         `json:"hash"`
}

// EventFilter is the server-side UI filter. Unknown values are rejected.
type EventFilter string

const (
	FilterAll         EventFilter = "all"
	FilterUnexpected  EventFilter = "unexpected"
	FilterPersistence EventFilter = "persistence"
	FilterSecurity    EventFilter = "security"
	FilterQuarantine  EventFilter = "quarantine"
)

// ValidFilter rejects arbitrary client filter strings.
func ValidFilter(value EventFilter) bool {
	switch value {
	case FilterAll, FilterUnexpected, FilterPersistence, FilterSecurity, FilterQuarantine:
		return true
	default:
		return false
	}
}

// SensorState is the honest health of one collection path.
type SensorState string

const (
	SensorHealthy     SensorState = "HEALTHY"
	SensorDegraded    SensorState = "DEGRADED"
	SensorUnavailable SensorState = "UNAVAILABLE"
	SensorStopped     SensorState = "STOPPED"
)

// SensorStatus is rendered directly by the Titan status surface.
type SensorStatus struct {
	ID           string      `json:"id"`
	Label        string      `json:"label"`
	State        SensorState `json:"state"`
	Detail       string      `json:"detail,omitempty"`
	LastEventUTC time.Time   `json:"lastEventUtc,omitempty"`
	Events       uint64      `json:"events"`
	Errors       uint64      `json:"errors"`
}

// WatchRoot is one recursive file-system collection boundary.
type WatchRoot struct {
	Path   string    `json:"path"`
	Class  RiskClass `json:"class"`
	Active bool      `json:"active"`
	Error  string    `json:"error,omitempty"`
}

// Permit is a short-lived, scoped owner authorization. It is deliberately
// narrower than an administrator account: path + optional hash + action +
// expiry. Single-use permits are consumed by the first matching event.
type Permit struct {
	ID         string    `json:"id"`
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256,omitempty"`
	Action     string    `json:"action"`
	CreatedUTC time.Time `json:"createdUtc"`
	ExpiresUTC time.Time `json:"expiresUtc"`
	SingleUse  bool      `json:"singleUse"`
	Used       bool      `json:"used"`
	Reason     string    `json:"reason"`
}

// Policy is the owner's authorization document. Titan does not infer
// authorization from administrator rights, signatures or remote tools.
type Policy struct {
	SchemaVersion    int      `json:"schemaVersion"`
	Mode             string   `json:"mode"`
	AutoQuarantine   bool     `json:"autoQuarantine"`
	Permits          []Permit `json:"permits"`
	DevelopmentRoots []string `json:"developmentRoots"`
	// OwnerProcessImages is an explicit owner-approved toolchain allowlist of
	// absolute image paths. A match only downgrades ingress/user-content changes
	// to TOLERATED; it never authorizes system, persistence or security changes.
	OwnerProcessImages []string `json:"ownerProcessImages,omitempty"`
	// CorrelateWithKillerdom authorizes active kinetic response coordination
	// with the Killerdom process enforcement engine when severe system compromise
	// is observed with proven process attribution.
	CorrelateWithKillerdom bool      `json:"correlateWithKillerdom,omitempty"`
	UpdatedUTC             time.Time `json:"updatedUtc"`
	Reason                 string    `json:"reason"`
	// ClockHighWaterUTC is the highest wall-clock timestamp observed by the
	// policy store. It is persisted so a clock rollback across a restart cannot
	// silently extend expired permits (DP-FIND-014).
	ClockHighWaterUTC time.Time `json:"clockHighWaterUtc,omitempty"`
}

const (
	PolicySchemaVersion = 1
	ModeObserve         = "OBSERVE"
	ModeContain         = "CONTAIN"
	ModeStrict          = "STRICT"

	// 5.3.0 Sovereign Titan Modes:
	ModeSimple     = "SIMPLE"
	ModeBalanced   = "BALANCED"
	ModeAggressive = "AGGRESSIVE"
	ModeParanoid   = "PARANOID"
)

// SecurityControl is the measured state of one critical security setting.
type SecurityControl struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Value    string   `json:"value"`
	Expected string   `json:"expected"`
	Secure   bool     `json:"secure"`
	Severity Severity `json:"severity"`
}

// BootTrust is the measured, intentionally incomplete boot picture. Nil means
// the value is not proven on this hardware; the UI must not render it green.
type BootTrust struct {
	SecureBoot   *bool     `json:"secureBoot"`
	TPM          *bool     `json:"tpm"`
	MeasuredBoot bool      `json:"measuredBoot"`
	CheckedUTC   time.Time `json:"checkedUtc,omitempty"`
	Detail       string    `json:"detail"`
}

// CheckpointStatus is the latest signed evidence anchor.
type CheckpointStatus struct {
	Sequence        uint64    `json:"sequence"`
	CreatedUTC      time.Time `json:"createdUtc,omitempty"`
	PublicKeySHA256 string    `json:"publicKeySha256,omitempty"`
	Signature       string    `json:"signature,omitempty"`
	Verified        bool      `json:"verified"`
	Detail          string    `json:"detail,omitempty"`
}

// WitnessStatus makes the limitation explicit: a local checkpoint is not an
// independent witness. The field becomes useful when a companion witness is
// configured and reachable.
type WitnessStatus struct {
	Configured        bool      `json:"configured"`
	Reachable         bool      `json:"reachable"`
	LastAckUTC        time.Time `json:"lastAckUtc,omitempty"`
	LastCheckpointUTC time.Time `json:"lastCheckpointUtc,omitempty"`
	Detail            string    `json:"detail"`
}

// VerificationResult is the result of re-verifying the local journal and all
// retained checkpoint signatures.
type VerificationResult struct {
	Verified      bool      `json:"verified"`
	Events        int       `json:"events"`
	Checkpoints   int       `json:"checkpoints"`
	CheckedUTC    time.Time `json:"checkedUtc"`
	FirstSequence uint64    `json:"firstSequence,omitempty"`
	LastSequence  uint64    `json:"lastSequence,omitempty"`
	Detail        string    `json:"detail,omitempty"`
}

// Status is the complete Titan projection consumed by the control center.
type Status struct {
	Version          string            `json:"version"`
	State            string            `json:"state"`
	TrustPosture     TrustStatus       `json:"trustPosture"`
	Mode             string            `json:"mode"`
	StartedUTC       time.Time         `json:"startedUtc,omitempty"`
	UptimeSeconds    int64             `json:"uptimeSeconds"`
	Sensors          []SensorStatus    `json:"sensors"`
	EventCount       uint64            `json:"eventCount"`
	OpenFindings     int               `json:"openFindings"`
	QuarantineCount  int               `json:"quarantineCount"`
	LastEventUTC     time.Time         `json:"lastEventUtc,omitempty"`
	LastCheckpoint   CheckpointStatus  `json:"lastCheckpoint"`
	JournalVerified  bool              `json:"journalVerified"`
	JournalError     string            `json:"journalError,omitempty"`
	Policy           Policy            `json:"policy"`
	WatchRoots       []WatchRoot       `json:"watchRoots"`
	SecurityControls []SecurityControl `json:"securityControls"`
	Boot             BootTrust         `json:"boot"`
	Witness          WitnessStatus     `json:"witness"`
	EventsDropped    uint64            `json:"eventsDropped"`
	WatcherOverflows uint64            `json:"watcherOverflows"`
	QuarantineBytes  int64             `json:"quarantineBytes"`
	CanQuarantine    bool              `json:"canQuarantine"`
	Limits           Limits            `json:"limits"`
}

// Limits is the published bound envelope for the UI.
type Limits struct {
	MaxEventsPerPage     int `json:"maxEventsPerPage"`
	MaxQuarantineMB      int `json:"maxQuarantineMb"`
	MaxPermits           int `json:"maxPermits"`
	MaxQuarantineEntries int `json:"maxQuarantineEntries"`
	MaxQuarantineTotalMB int `json:"maxQuarantineTotalMb"`
	MinDiskReserveMB     int `json:"minDiskReserveMb"`
}

// QuarantineEntry is the owner-visible state of one isolated object.
type QuarantineEntry struct {
	ID            string    `json:"id"`
	CreatedUTC    time.Time `json:"createdUtc"`
	OriginalPath  string    `json:"originalPath"`
	OriginalName  string    `json:"originalName"`
	SHA256        string    `json:"sha256"`
	Size          int64     `json:"size"`
	FileType      string    `json:"fileType,omitempty"`
	EventID       string    `json:"eventId,omitempty"`
	Reason        string    `json:"reason"`
	OriginalGone  bool      `json:"originalGone"`
	State         string    `json:"state"`
	Reviewed      bool      `json:"reviewed"`
	ReviewNote    string    `json:"reviewNote,omitempty"`
	RestoredUTC   time.Time `json:"restoredUtc,omitempty"`
	RestoreReason string    `json:"restoreReason,omitempty"`
	// MetadataMAC authenticates the metadata record with a key derived from the
	// service-local vault key, so the restore target and review state cannot be
	// rewritten by editing <id>.json (DP-FIND-015).
	MetadataMAC string `json:"metadataMac,omitempty"`
}

// EvidenceBundle is the bounded, signed export for independent review.
type EvidenceBundle struct {
	SchemaVersion   int                `json:"schemaVersion"`
	GeneratedUTC    time.Time          `json:"generatedUtc"`
	Version         string             `json:"version"`
	BootID          string             `json:"bootId"`
	Events          []Event            `json:"events"`
	Checkpoints     []Checkpoint       `json:"checkpoints"`
	Verification    VerificationResult `json:"verification"`
	PublicKeySHA256 string             `json:"publicKeySha256"`
	Limitations     []string           `json:"limitations"`
}

// Checkpoint is one signed journal anchor.
type Checkpoint struct {
	Sequence        uint64    `json:"sequence"`
	LastHash        string    `json:"lastHash"`
	CreatedUTC      time.Time `json:"createdUtc"`
	BootID          string    `json:"bootId"`
	PublicKeySHA256 string    `json:"publicKeySha256"`
	Signature       string    `json:"signature"`
}

// Notification is a bounded owner-facing projection of a Titan finding. It is
// deliberately not an attribution and carries no file content.
type Notification struct {
	ID           string    `json:"id"`
	TimestampUTC time.Time `json:"timestampUtc"`
	Kind         string    `json:"kind"`
	Severity     Severity  `json:"severity"`
	Title        string    `json:"title"`
	Detail       string    `json:"detail"`
}

// Observation is what a sensor emits before policy evaluation.
type Observation struct {
	Type          EventType
	Severity      Severity
	Object        Object
	Actor         Actor
	Network       NetworkContext
	Authorization Authorization
	Source        string
	Health        string
	Detail        string
	Response      Response
}
