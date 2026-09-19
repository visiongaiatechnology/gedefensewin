// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/integrity"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

const (
	maxReplayEntries    = 4096
	maxBootstrapEntries = 32
	maxSessionEntries   = 32
	maxRateEntries      = 16
)

type replayGuard struct {
	mu    sync.Mutex
	items map[string]time.Time
}

type rateWindow struct {
	started time.Time
	count   int
}

type Server struct {
	version        string
	token          string
	engine         HardeningEngine
	audit          AuditEngine
	xdr            XDREngine
	mhx            MHXEngine
	integrity      IntegrityEngine
	ledger         *evidence.Ledger
	replay         replayGuard
	sessionMu      sync.Mutex
	bootstrapCodes map[string]time.Time
	sessions       map[string]time.Time
	rateMu         sync.Mutex
	rates          map[string]rateWindow
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
}

type IntegrityEngine interface {
	Status() integrity.Status
	Configure(bool, int) (integrity.Status, error)
	Start() error
	Changes(int, int) ([]integrity.Change, error)
}
