// STATUS: DIAMANT VGT SUPREME
package threatintel

import "time"

const (
	SyncInterval                 = 12 * time.Hour
	FailureRetryInterval         = 15 * time.Minute
	SchemaVersion                = 2
	maximumEnforcementIndicators = 250000
)

type Action string

const (
	ActionAnnotateOnly  Action = "ANNOTATE_ONLY"
	ActionCorrelateOnly Action = "CORRELATE_ONLY"
	ActionBlock         Action = "BLOCK"
)

func (a Action) rank() int {
	switch a {
	case ActionBlock:
		return 3
	case ActionCorrelateOnly:
		return 2
	case ActionAnnotateOnly:
		return 1
	default:
		return 0
	}
}

type FeedFormat string

const (
	FormatPlain  FeedFormat = "plain"
	FormatNDJSON FeedFormat = "ndjson"
)

type Source struct {
	Key              string
	Name             string
	URL              string
	Format           FeedFormat
	Action           Action
	MaximumBytes     int64
	RequiresMetadata bool
}

type Attribution struct {
	Name                string `json:"name"`
	URL                 string `json:"url"`
	Copyright           string `json:"copyright,omitempty"`
	Terms               string `json:"terms,omitempty"`
	SourceTimestampUnix int64  `json:"sourceTimestampUnix,omitempty"`
}

type FeedState struct {
	Key            string    `json:"key"`
	Name           string    `json:"name"`
	Action         Action    `json:"action"`
	State          string    `json:"state"`
	Indicators     int       `json:"indicators"`
	LastAttemptUTC time.Time `json:"lastAttemptUtc,omitempty"`
	LastSuccessUTC time.Time `json:"lastSuccessUtc,omitempty"`
	Error          string    `json:"error,omitempty"`

	// Per-feed authority projection (V5). Action stays the immutable catalog
	// authority for backward compatibility; these fields expose the operator
	// override and the authority the compiler actually applied.
	DefaultAction    Action `json:"defaultAction,omitempty"`
	ConfiguredAction Action `json:"configuredAction,omitempty"`
	EffectiveAction  Action `json:"effectiveAction,omitempty"`
	ActionSource     string `json:"actionSource,omitempty"`

	// Signed-authority and hard-TTL projection.
	AuthorityVerified      bool      `json:"authorityVerified"`
	AuthoritySequence      uint64    `json:"authoritySequence,omitempty"`
	AuthorityValidUntilUTC time.Time `json:"authorityValidUntilUtc,omitempty"`
}

type Status struct {
	LastAttemptUTC        time.Time   `json:"lastAttemptUtc"`
	LastSuccessUTC        time.Time   `json:"lastSuccessUtc"`
	NextSyncUTC           time.Time   `json:"nextSyncUtc"`
	Indicators            int         `json:"indicators"`
	BlockingIndicators    int         `json:"blockingIndicators"`
	BlockingFeedsReady    int         `json:"blockingFeedsReady"`
	BlockingFeedsTotal    int         `json:"blockingFeedsTotal"`
	CorrelationIndicators int         `json:"correlationIndicators"`
	AnnotationIndicators  int         `json:"annotationIndicators"`
	Generation            string      `json:"generationSha256"`
	EnforcementGeneration string      `json:"enforcementGenerationSha256"`
	ProtectedPrefixes     int         `json:"protectedPrefixes"`
	ProtectionGeneration  string      `json:"protectionGenerationSha256"`
	State                 string      `json:"state"`
	Error                 string      `json:"error,omitempty"`
	Feeds                 []FeedState `json:"feeds"`

	// Polling policy projection. The values are derived from the persisted
	// manager polling configuration; they are never inferred by the UI.
	PollingIntervalSeconds        int       `json:"pollingIntervalSeconds"`
	PollingIntervalSource         string    `json:"pollingIntervalSource"`
	PollingIntervalMinSeconds     int       `json:"pollingIntervalMinSeconds"`
	PollingIntervalMaxSeconds     int       `json:"pollingIntervalMaxSeconds"`
	PollingIntervalDefaultSeconds int       `json:"pollingIntervalDefaultSeconds"`
	PollingUpdatedUTC             time.Time `json:"pollingUpdatedUtc,omitempty"`

	// Per-feed policy store projection (V5).
	FeedPolicySource     string    `json:"feedPolicySource,omitempty"`
	FeedPolicyUpdatedUTC time.Time `json:"feedPolicyUpdatedUtc,omitempty"`
	FeedPolicyOverrides  int       `json:"feedPolicyOverrides"`
	FeedPolicyError      string    `json:"feedPolicyError,omitempty"`

	// Feed authenticity / freshness projection (DP-FIND-002/003/014).
	FeedAuthenticity      string `json:"feedAuthenticity"`
	FeedAuthorityKeys     int    `json:"feedAuthorityKeys"`
	FeedAuthoritySequence uint64 `json:"feedAuthoritySequence"`
	FeedAuthorityError    string `json:"feedAuthorityError,omitempty"`
	FeedClockRollback     bool   `json:"feedClockRollback"`
	MaxFeedAgeSeconds     int    `json:"maxFeedAgeSeconds"`
}

type Match struct {
	Found     bool     `json:"found"`
	Protected bool     `json:"protected,omitempty"`
	Action    Action   `json:"action,omitempty"`
	Sources   []string `json:"sources,omitempty"`
}

type sourceSnapshot struct {
	SchemaVersion    int         `json:"schemaVersion"`
	Key              string      `json:"key"`
	GeneratedUTC     time.Time   `json:"generatedUtc"`
	Action           Action      `json:"action"`
	Attribution      Attribution `json:"attribution"`
	GenerationSHA256 string      `json:"generationSha256"`
	Indicators       []string    `json:"indicators"`
	// Authority is the detached Ed25519 signed attestation for this exact
	// generation (DP-FIND-002). It is embedded so a cached snapshot can be
	// re-verified offline, without network access or the original feed body.
	Authority *feedAuthorityDocument `json:"authority,omitempty"`
}

type enforcementSnapshot struct {
	SchemaVersion              int       `json:"schemaVersion"`
	GeneratedUTC               time.Time `json:"generatedUtc"`
	GenerationSHA256           string    `json:"generationSha256"`
	ProtectionGenerationSHA256 string    `json:"protectionGenerationSha256"`
	ProtectedPrefixCount       int       `json:"protectedPrefixCount"`
	BlockIndicators            []string  `json:"blockIndicators"`
	BlockingFeedCount          int       `json:"blockingFeedCount"`
}
