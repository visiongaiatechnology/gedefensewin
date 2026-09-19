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
