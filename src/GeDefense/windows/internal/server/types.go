// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/geoip"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/integrity"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/startup"
	"github.com/visiongaiatechnology/gedefense/windows/internal/titan"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

const (
	maxReplayEntries         = 4096
	maxBootstrapEntries      = 32
	maxBrowserRegistrations  = 8
	maxSessionEntries        = 64
	maxRateEntries           = 256
	sessionIDPrefix          = "vgs."
	sessionTokenBodyLength   = 43
	sessionAbsoluteLifetime  = 2 * time.Hour
	sessionIdleLifetime      = 20 * time.Minute
	sessionRotationInterval  = 15 * time.Minute
	sessionRotationGrace     = 30 * time.Second
	bootstrapCodeLifetime    = 60 * time.Second
	browserRegistrationTTL   = 60 * time.Second
	maxSessionTokensPerAdmin = 43200 // 12 hours, lifetime upper bound
	minSessionLifetime       = time.Minute
	defaultServiceLifetime   = 4 * time.Hour
)

// scope is a functional authorization scope bound to a session. The local
// operator is still one human; scopes separate the browser console session, the
// window-host session and restricted read-only/service sessions without an
// external identity provider (AN-FIND-001/004).
type scope uint8

const (
	scopeRead scope = 1 << iota
	scopeOperate
	scopePolicy
	scopeWindow

	scopeAll = scopeRead | scopeOperate | scopePolicy | scopeWindow
)

func (s scope) has(required scope) bool {
	if required == 0 {
		return true
	}
	return s&required == required
}

func (s scope) names() []string {
	names := make([]string, 0, 4)
	if s.has(scopeRead) {
		names = append(names, "read")
	}
	if s.has(scopeOperate) {
		names = append(names, "operate")
	}
	if s.has(scopePolicy) {
		names = append(names, "policy")
	}
	if s.has(scopeWindow) {
		names = append(names, "window")
	}
	return names
}

func normaliseScopeList(values []string) (scope, bool) {
	var result scope
	if len(values) == 0 || len(values) > 4 {
		return 0, false
	}
	for _, value := range values {
		switch value {
		case "read":
			result |= scopeRead
		case "operate":
			result |= scopeOperate
		case "policy":
			result |= scopePolicy
		case "window":
			result |= scopeWindow
		default:
			return 0, false
		}
	}
	return result, result != 0
}

// sessionRecord is a server-side session. The raw token is only used as the map
// key and cookie/bearer value; roles/scopes, client identity, absolute expiry,
// idle expiry and rotation state live on the server, never in the cookie.
type sessionRecord struct {
	token              string
	client             string
	scopes             scope
	issuedAt           time.Time
	expires            time.Time
	idleExpires        time.Time
	previousToken      string
	previousValidUntil time.Time
	// operator is true for sessions minted by the loopback operator broker after
	// the server verified the requesting OS process token (operator group or
	// Administrators). subjectAccount/subjectSID are the audited OS identity and
	// are never secrets (UI-FIND-001 / AN-FIND-001).
	operator       bool
	subjectAccount string
	subjectSID     string
}

type bootstrapCode struct {
	expires time.Time
	scopes  scope
	client  string
}

// browserRegistration is the short-lived, master-authorized expectation that a
// specific browser process will exchange a session. It is the replacement for
// passing the bootstrap secret as a Chromium command-line argument
// (AN-FIND-002/UI-FIND-004).
type browserRegistration struct {
	pid     uint32
	expires time.Time
	scopes  scope
	client  string
}

type rateClass int

const (
	rateRead rateClass = iota
	rateOperate
	ratePolicy
	rateLong
)

type rateBucket struct {
	started  time.Time
	counts   map[rateClass]int
	lastSeen time.Time
}

type replayGuard struct {
	mu    sync.Mutex
	items map[string]time.Time
}

// authContext describes how a request was authenticated. The browser console and
// the window host are distinct clients with distinct scopes; the master file
// credential remains the local break-glass authority. Expiry values are copied
// while the session lock is held so handlers never read a session record that a
// concurrent request may be rotating.
type authContext struct {
	master      bool
	session     *sessionRecord
	token       string
	client      string
	scopes      scope
	viaCookie   bool
	expires     time.Time
	idleExpires time.Time
}

func (a authContext) scopeNames() []string {
	if a.master {
		return scopeAll.names()
	}
	return a.scopes.names()
}

func (a authContext) identity() string {
	if a.master {
		return "master"
	}
	if a.session != nil {
		return "session:" + a.client
	}
	return "anonymous"
}

type Server struct {
	geoOnce sync.Once
	geo     *geoip.GeoResolver
	version string
	// master token: the installer-provisioned break-glass file credential. Since
	// 5.1.4 it is SYSTEM/Administrators-only; Center and Tray never read it and
	// instead obtain short-lived scoped sessions from the loopback operator
	// broker after the service verified their Windows token (operator group or
	// Administrators). The broker session is audited with the OS account, can be
	// revoked (logout/revoke-all) and the master credential can be rotated
	// without touching clients (UI-FIND-001 / AN-FIND-001 / AN-FIND-004).
	tokenMu     sync.RWMutex
	token       string
	engine      HardeningEngine
	audit       AuditEngine
	xdr         XDREngine
	mhx         MHXEngine
	integrity   IntegrityEngine
	titan       TitanEngine
	ledger      *evidence.Ledger
	startupGate *startup.State
	settings    SettingsService
	replay      replayGuard

	sessionMu            sync.Mutex
	bootstrapCodes       map[string]bootstrapCode
	sessions             map[string]*sessionRecord
	browserRegistrations []browserRegistration

	rateMu sync.Mutex
	rates  map[string]*rateBucket

	windowMu       sync.Mutex
	windowCommands chan string
	windowStateVal string
	windowClientAt time.Time

	// now is the session/rate clock. It is time.Now in production and may be
	// replaced by deterministic tests.
	now func() time.Time
	// peerPID resolves the operating-system process id that owns a loopback TCP
	// peer address ("127.0.0.1:port"). It exists so the browser bootstrap can be
	// bound to the process the launcher actually started. Tests inject a
	// deterministic replacement; a lookup error always fails closed.
	peerPID func(remoteAddr string) (uint32, error)
	// operatorPeer resolves a process id to a verified Windows token identity
	// (account SID, name, group membership). It is the local authorization
	// source of the operator session broker so Center/Tray never need to read
	// the long-lived master token file (UI-FIND-001 / AN-FIND-004). Tests inject
	// a deterministic replacement; every error fails closed.
	operatorPeer func(pid uint32) (operatorPeer, error)
}

func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Server) masterToken() string {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	return s.token
}

func (s *Server) setMasterToken(token string) {
	s.tokenMu.Lock()
	s.token = token
	s.tokenMu.Unlock()
}

func (s *Server) peerProcessID(remoteAddr string) (uint32, error) {
	if s.peerPID != nil {
		return s.peerPID(remoteAddr)
	}
	return lookupPeerProcessID(remoteAddr)
}

func (s *Server) resolveOperatorPeer(pid uint32) (operatorPeer, error) {
	if s.operatorPeer != nil {
		return s.operatorPeer(pid)
	}
	return operatorPeerFromPID(pid)
}

type HardeningEngine interface {
	Audit(context.Context) (hardening.Result, error)
	Posture(context.Context) (hardening.Result, error)
	Enforce(context.Context, string) (hardening.Result, error)
	Components(context.Context) ([]hardening.ComponentStatus, error)
	EnforceComponent(context.Context, string) ([]hardening.ComponentStatus, error)
	Rollback(context.Context) (hardening.Result, error)
}

type AuditEngine interface {
	Run(context.Context) (audit.Result, error)
}

type XDREngine interface {
	Scan(context.Context) (xdr.Result, error)
	Last() xdr.Result
}

type MHXEngine interface {
	Status() mhx.Status
	Analyses(int) []mhx.Analysis
	NetworkFindings(int) []mhx.NetworkFinding
	AttackStories(int) []mhx.AttackStory
	SetMode(context.Context, string) error
	SyncFeeds(context.Context) error
	ProtectedNetworkPolicy() mhx.ProtectedNetworkPolicy
	SetProtectedNetworkPolicy(context.Context, []string) (mhx.ProtectedNetworkPolicy, error)
	Applications(context.Context) ([]mhx.ApplicationAllow, error)
	SetApplication(context.Context, string, string) ([]mhx.ApplicationAllow, error)
	ReconcilePolicy(context.Context) error
}

type IntegrityEngine interface {
	Status() integrity.Status
	Configure(bool, int) (integrity.Status, error)
	Start() error
	Changes(int, int) ([]integrity.Change, error)
}

// TitanEngine is the narrow server boundary for the Titan integrity module.
// The control plane never inspects internal sensor state directly.
type TitanEngine interface {
	Status() titan.Status
	Policy() titan.Policy
	Events(int, int, titan.EventFilter) ([]titan.Event, int, error)
	QuarantineEntries() []titan.QuarantineEntry
	QuarantineEvent(string, string) (titan.QuarantineEntry, error)
	RestoreQuarantine(string, string) (titan.QuarantineEntry, error)
	ReviewQuarantine(string, string) (titan.QuarantineEntry, error)
	SetPolicy(string, bool, string) (titan.Policy, error)
	SetOwnerProcessImages([]string, string) (titan.Policy, error)
	Permits() []titan.Permit
	CreatePermit(string, string, string, time.Duration, bool, string) (titan.Permit, error)
	RevokePermit(string, string) (titan.Policy, error)
	AddDevelopmentRoot(string, string) (titan.Policy, error)
	RemoveDevelopmentRoot(string, string) (titan.Policy, error)
	AcknowledgeEvent(string, string) error
	AcknowledgeOpenFindings(int, string) (int, error)
	Checkpoints(int) []titan.Checkpoint
	Verify() titan.VerificationResult
	Export(int) (titan.EvidenceBundle, error)
	Notifications(int) []titan.Notification
}
