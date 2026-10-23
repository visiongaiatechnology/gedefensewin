// STATUS: DIAMANT VGT SUPREME
package server

import (
	"embed"
	"io/fs"
	"net/http"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/startup"
)

//go:embed web/*
var assets embed.FS

// Typed confirmation phrases for security-reducing mutations. They are public
// constants (not secrets); the security property is the server-side enforcement
// of phrase + operator reason + replay guard before the handler runs
// (AN-FIND-005 / UI-FIND-003).
const (
	confirmationHardeningProfile      = "APPLY HARDENING PROFILE"
	confirmationHardeningRollback     = "ROLLBACK HARDENING"
	confirmationHardeningComponent    = "ENABLE HARDENING COMPONENT"
	confirmationIntegrityMonitoring   = "CHANGE INTEGRITY MONITORING"
	confirmationApplicationAllowlist  = "UPDATE APPLICATION ALLOWLIST"
	confirmationAddDevelopmentRoot    = "ADD DEVELOPMENT ROOT"
	confirmationRemoveDevelopmentRoot = "REMOVE DEVELOPMENT ROOT"
	confirmationOwnerProcessImages    = "UPDATE OWNER PROCESS IMAGES"
	setupConfirmation                 = "COMPLETE SETUP"
)

func New(version, token string, engine HardeningEngine, auditEngine AuditEngine, xdrEngine XDREngine, mhxEngine MHXEngine, integrityEngine IntegrityEngine, ledger *evidence.Ledger) http.Handler {
	return NewWithStartup(version, token, engine, auditEngine, xdrEngine, mhxEngine, integrityEngine, ledger, nil, nil)
}

func NewWithStartup(version, token string, engine HardeningEngine, auditEngine AuditEngine, xdrEngine XDREngine, mhxEngine MHXEngine, integrityEngine IntegrityEngine, ledger *evidence.Ledger, startupGate *startup.State, settingsService SettingsService) http.Handler {
	_, handler := newServer(version, token, engine, auditEngine, xdrEngine, mhxEngine, integrityEngine, ledger, startupGate, settingsService, nil)
	return handler
}

// NewWithTitan composes the V5 control plane together with the Titan module.
// The existing constructor remains stable for callers that do not expose Titan.
func NewWithTitan(version, token string, engine HardeningEngine, auditEngine AuditEngine, xdrEngine XDREngine, mhxEngine MHXEngine, integrityEngine IntegrityEngine, ledger *evidence.Ledger, startupGate *startup.State, settingsService SettingsService, titanEngine TitanEngine) http.Handler {
	_, handler := newServer(version, token, engine, auditEngine, xdrEngine, mhxEngine, integrityEngine, ledger, startupGate, settingsService, titanEngine)
	return handler
}

// newServer returns the control-plane state and its HTTP handler so tests can
// drive sessions, rotation and rate budgets with a deterministic clock.
func newServer(version, token string, engine HardeningEngine, auditEngine AuditEngine, xdrEngine XDREngine, mhxEngine MHXEngine, integrityEngine IntegrityEngine, ledger *evidence.Ledger, startupGate *startup.State, settingsService SettingsService, titanEngine TitanEngine) (*Server, http.Handler) {
	s := &Server{
		version: version, token: token, engine: engine, audit: auditEngine, xdr: xdrEngine, mhx: mhxEngine,
		integrity: integrityEngine, titan: titanEngine, ledger: ledger, startupGate: startupGate, settings: settingsService,
		replay:               replayGuard{items: make(map[string]time.Time)},
		bootstrapCodes:       make(map[string]bootstrapCode),
		sessions:             make(map[string]*sessionRecord),
		browserRegistrations: make([]browserRegistration, 0, maxBrowserRegistrations),
		rates:                make(map[string]*rateBucket),
		windowCommands:       make(chan string, 1), windowStateVal: "normal",
	}
	return s, s.routes()
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	webRoot, err := fs.Sub(assets, "web")
	if err != nil {
		mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
			s.writeError(w, http.StatusInternalServerError, "asset unavailable")
		})
		return s.headers(mux)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(webRoot))))
	mux.HandleFunc("GET /", s.index)

	// Public session establishment. The exchange itself performs origin, replay,
	// rate-limit and process-binding checks. The operator broker is the
	// OS-identity-bound, non-secret replacement for Center/Tray file-token
	// reads; it rejects browsers and non-operator OS tokens fail-closed
	// (UI-FIND-001 / AN-FIND-004).
	mux.HandleFunc("POST /api/v1/session/exchange", s.exchange)
	mux.HandleFunc("POST /api/v1/session/operator", s.operatorBroker)

	// Break-glass / administrative routes require the file master credential.
	master := func(pattern string, handler http.HandlerFunc) {
		mux.HandleFunc("POST "+pattern, s.masterAuthorize(handler))
	}
	master("/api/v1/session/bootstrap", s.bootstrap)
	master("/api/v1/admin/sessions", s.adminCreateSession)
	master("/api/v1/admin/sessions/revoke-all", s.revokeAllSessions)
	master("/api/v1/admin/token/reload", s.reloadMasterToken)
	master("/api/v1/admin/token/rotate", s.rotateMasterToken)

	// The privileged browser registration is available to the break-glass
	// credential and to an OS-identity-verified operator broker session.
	mux.HandleFunc("POST /api/v1/session/register-browser", s.operatorAuthorize(s.registerBrowser))

	// Authenticated session lifecycle (cookie or scoped bearer session).
	route := func(method, pattern string, mode routeAuthMode, confirmation string, handler http.HandlerFunc) {
		mux.HandleFunc(method+" "+pattern, s.protected(mode, confirmation, handler))
	}
	route(http.MethodPost, "/api/v1/session/logout", authRead, "", s.sessionLogout)
	route(http.MethodGet, "/api/v1/session/state", authRead, "", s.sessionState)

	// Window host routes: master credential or a window-scoped session.
	window := func(method, pattern string, handler http.HandlerFunc) {
		mux.HandleFunc(method+" "+pattern, s.windowAuthorize(handler))
	}
	window(http.MethodGet, "/api/v1/window/poll", s.windowPoll)
	window(http.MethodPost, "/api/v1/window/ack", s.windowAck)
	window(http.MethodPost, "/api/v1/window/minimize", s.windowMinimize)
	window(http.MethodPost, "/api/v1/window/maximize", s.windowMaximize)
	window(http.MethodPost, "/api/v1/window/drag", s.windowDrag)
	window(http.MethodPost, "/api/v1/window/close", s.windowClose)
	window(http.MethodGet, "/api/v1/window/state", s.windowState)

	read := func(pattern string, handler http.HandlerFunc) {
		route(http.MethodGet, pattern, authRead, "", handler)
	}
	operate := func(pattern string, handler http.HandlerFunc) {
		route(http.MethodPost, pattern, authOperate, "", handler)
	}
	policy := func(pattern string, handler http.HandlerFunc) {
		route(http.MethodPost, pattern, authPolicy, "", handler)
	}
	confirmed := func(pattern, confirmation string, handler http.HandlerFunc) {
		route(http.MethodPost, pattern, authPolicy, confirmation, handler)
	}

	read("/api/v1/health/status", s.healthStatus)
	operate("/api/v1/health/refresh", s.healthRefresh)
	read("/api/v1/startup/state", s.startupStatus)
	read("/api/v1/setup/status", s.setupStatus)
	confirmed("/api/v1/setup/complete", setupConfirmation, s.setupComplete)
	operate("/api/v1/startup/ack", s.startupAcknowledge)
	read("/api/v1/status", s.status)
	read("/api/v1/protection/readiness", s.protectionReadiness)
	read("/api/v1/evidence", s.evidenceSnapshot)
	read("/api/v1/evidence/page", s.evidencePage)
	operate("/api/v1/evidence/verify", s.verifyEvidence)
	read("/api/v1/settings", s.settingsSnapshot)
	read("/api/v1/settings/catalog", s.settingsCatalog)
	policy("/api/v1/settings", s.settingsApply)
	read("/api/v1/settings/profiles", s.settingsProfiles)
	policy("/api/v1/settings/profiles", s.settingsProfileMutation)
	confirmed("/api/v1/hardening/enforce", confirmationHardeningProfile, s.enforce)
	read("/api/v1/hardening/components", s.hardeningComponents)
	read("/api/v1/hardening/catalog", s.hardeningCatalog)
	read("/api/v1/defender/telemetry", s.defenderTelemetry)
	policy("/api/v1/hardening/settings", s.applyHardeningSettings)
	confirmed("/api/v1/hardening/components", confirmationHardeningComponent, s.enforceHardeningComponent)
	confirmed("/api/v1/hardening/rollback", confirmationHardeningRollback, s.rollback)
	operate("/api/v1/audit/run", s.runAudit)
	read("/api/v1/xdr/findings", s.xdrFindings)
	operate("/api/v1/xdr/scan", s.runXDR)
	read("/api/v1/mhx/status", s.mhxStatus)
	read("/api/v1/mhx/settings", s.mhxSettings)
	policy("/api/v1/mhx/settings", s.mhxSetSettings)
	read("/api/v1/kinetic/settings", s.kineticSettings)
	policy("/api/v1/kinetic/settings", s.kineticSetSettings)
	read("/api/v1/threat-intel/status", s.threatIntelStatus)
	policy("/api/v1/threat-intel/settings", s.threatIntelSetSettings)
	read("/api/v1/mhx/threat-intelligence/feed-policy", s.mhxFeedPolicy)
	policy("/api/v1/mhx/threat-intelligence/feed-policy", s.mhxSetFeedPolicy)
	read("/api/v1/notifications", s.notifications)
	read("/api/v1/mhx/geo", s.kineticGeo)
	read("/api/v1/overview/threat-map", s.overviewThreatMap)
	policy("/api/v1/mhx/kinetic/mode", s.kineticSetMode)
	read("/api/v1/mhx/analyses", s.mhxAnalyses)
	read("/api/v1/mhx/network", s.mhxNetwork)
	read("/api/v1/mhx/stories", s.mhxStories)
	operate("/api/v1/mhx/feeds/sync", s.mhxSyncFeeds)
	read("/api/v1/mhx/threat-intelligence/protected-networks", s.mhxProtectedNetworks)
	policy("/api/v1/mhx/threat-intelligence/protected-networks", s.mhxSetProtectedNetworks)
	policy("/api/v1/mhx/mode", s.mhxSetMode)
	read("/api/v1/mhx/applications", s.mhxApplications)
	confirmed("/api/v1/mhx/applications", confirmationApplicationAllowlist, s.mhxSetApplication)
	read("/api/v1/mhx/application-denies", s.mhxApplicationDenies)
	policy("/api/v1/mhx/application-denies", s.mhxSetApplicationDeny)
	operate("/api/v1/mhx/policy/reconcile", s.mhxReconcilePolicy)
	read("/api/v1/integrity/status", s.integrityStatus)
	read("/api/v1/integrity/changes", s.integrityChanges)
	confirmed("/api/v1/integrity/configuration", confirmationIntegrityMonitoring, s.integrityConfiguration)
	operate("/api/v1/integrity/scan", s.integrityScan)
	read("/api/v1/titan/status", s.titanStatus)
	read("/api/v1/titan/events", s.titanEvents)
	read("/api/v1/titan/quarantine", s.titanQuarantine)
	policy("/api/v1/titan/events/{id}/quarantine", s.titanQuarantineEvent)
	operate("/api/v1/titan/events/{id}/acknowledge", s.titanAcknowledgeEvent)
	operate("/api/v1/titan/events/acknowledge", s.titanAcknowledgeOpenFindings)
	policy("/api/v1/titan/quarantine/{id}/restore", s.titanRestore)
	policy("/api/v1/titan/quarantine/{id}/review", s.titanReview)
	read("/api/v1/titan/policy", s.titanPolicy)
	policy("/api/v1/titan/policy", s.titanSetPolicy)
	read("/api/v1/titan/permits", s.titanPermits)
	policy("/api/v1/titan/permits", s.titanCreatePermit)
	policy("/api/v1/titan/permits/{id}/revoke", s.titanRevokePermit)
	confirmed("/api/v1/titan/development-roots", confirmationAddDevelopmentRoot, s.titanAddDevelopmentRoot)
	confirmed("/api/v1/titan/development-roots/remove", confirmationRemoveDevelopmentRoot, s.titanRemoveDevelopmentRoot)
	confirmed("/api/v1/titan/owner-process-images", confirmationOwnerProcessImages, s.titanSetOwnerProcessImages)
	read("/api/v1/titan/checkpoints", s.titanCheckpoints)
	operate("/api/v1/titan/verify", s.titanVerify)
	read("/api/v1/titan/export", s.titanExport)
	return s.headers(mux)
}
