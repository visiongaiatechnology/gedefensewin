// STATUS: DIAMANT VGT SUPREME
package server

import (
	"embed"
	"io/fs"
	"net/http"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
)

//go:embed web/*
var assets embed.FS

func New(version, token string, engine HardeningEngine, auditEngine AuditEngine, xdrEngine XDREngine, mhxEngine MHXEngine, integrityEngine IntegrityEngine, ledger *evidence.Ledger) http.Handler {
	s := &Server{
		version: version, token: token, engine: engine, audit: auditEngine, xdr: xdrEngine, mhx: mhxEngine,
		integrity: integrityEngine, ledger: ledger,
		replay:         replayGuard{items: make(map[string]time.Time)},
		bootstrapCodes: make(map[string]time.Time), sessions: make(map[string]time.Time), rates: make(map[string]rateWindow),
	}
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
	mux.HandleFunc("POST /api/v1/session/bootstrap", s.masterAuthorize(s.bootstrap))
	mux.HandleFunc("POST /api/v1/session/exchange", s.exchange)
	mux.HandleFunc("GET /api/v1/status", s.authorize(s.status))
	mux.HandleFunc("GET /api/v1/protection/readiness", s.authorize(s.protectionReadiness))
	mux.HandleFunc("GET /api/v1/evidence", s.authorize(s.evidenceSnapshot))
	mux.HandleFunc("POST /api/v1/evidence/verify", s.authorize(s.verifyEvidence))
	mux.HandleFunc("POST /api/v1/hardening/enforce", s.authorize(s.enforce))
	mux.HandleFunc("GET /api/v1/hardening/components", s.authorize(s.hardeningComponents))
	mux.HandleFunc("POST /api/v1/hardening/components", s.authorize(s.enforceHardeningComponent))
	mux.HandleFunc("POST /api/v1/hardening/rollback", s.authorize(s.rollback))
	mux.HandleFunc("POST /api/v1/audit/run", s.authorize(s.runAudit))
	mux.HandleFunc("GET /api/v1/xdr/findings", s.authorize(s.xdrFindings))
	mux.HandleFunc("POST /api/v1/xdr/scan", s.authorize(s.runXDR))
	mux.HandleFunc("GET /api/v1/mhx/status", s.authorize(s.mhxStatus))
	mux.HandleFunc("GET /api/v1/mhx/analyses", s.authorize(s.mhxAnalyses))
	mux.HandleFunc("GET /api/v1/mhx/network", s.authorize(s.mhxNetwork))
	mux.HandleFunc("GET /api/v1/mhx/stories", s.authorize(s.mhxStories))
	mux.HandleFunc("POST /api/v1/mhx/feeds/sync", s.authorize(s.mhxSyncFeeds))
	mux.HandleFunc("GET /api/v1/mhx/threat-intelligence/protected-networks", s.authorize(s.mhxProtectedNetworks))
	mux.HandleFunc("POST /api/v1/mhx/threat-intelligence/protected-networks", s.authorize(s.mhxSetProtectedNetworks))
	mux.HandleFunc("POST /api/v1/mhx/mode", s.authorize(s.mhxSetMode))
	mux.HandleFunc("GET /api/v1/mhx/applications", s.authorize(s.mhxApplications))
	mux.HandleFunc("POST /api/v1/mhx/applications", s.authorize(s.mhxSetApplication))
	mux.HandleFunc("GET /api/v1/integrity/status", s.authorize(s.integrityStatus))
	mux.HandleFunc("GET /api/v1/integrity/changes", s.authorize(s.integrityChanges))
	mux.HandleFunc("POST /api/v1/integrity/configuration", s.authorize(s.integrityConfiguration))
	mux.HandleFunc("POST /api/v1/integrity/scan", s.authorize(s.integrityScan))
	return s.headers(mux)
}
