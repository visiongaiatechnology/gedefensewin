// STATUS: PLATIN VGT SUPREME
package server

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/integrity"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/startup"
	"github.com/visiongaiatechnology/gedefense/windows/internal/titan"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

// newSetupFlowTestServer builds a control plane with the server-authoritative
// first-run state incomplete, which is exactly the production situation the
// wizard runs in.
func newSetupFlowTestServer(t *testing.T) (*Server, http.Handler, *startup.State) {
	t.Helper()
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	gate, err := startup.Open(filepath.Join(root, "startup-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	titanEngine, err := titan.New(filepath.Join(root, "titan"), "5.3.0", ledger)
	if err != nil {
		t.Fatal(err)
	}
	engine := fixedEngine{result: hardening.Result{
		Defender: true, DefenderService: true, RealTimeProtection: true,
		ASRRules: 11, ASRBlockRules: 11, ControlledFolderAccess: true,
	}}
	server, handler := newServer("5.3.0", testMasterToken, engine,
		fixedAudit{result: audit.Result{Checks: []audit.Check{}}},
		fixedXDR{result: xdr.Result{Findings: []xdr.Finding{}}},
		&fixedMHX{mode: "guarded", status: mhx.Status{Realtime: true, ProtectionHealth: "VERIFIED"}},
		&fixedIntegrity{status: integrity.Status{Enabled: true, State: "SCHEDULED"}},
		ledger, gate, nil, titanEngine)
	t.Cleanup(func() { _ = titanEngine.Close() })
	return server, handler, gate
}

// TestFirstRunSetupFlowIsNotRateLimited is the FIND-WIN-018 regression for the
// broken wizard: the documented three-call setup sequence must succeed for one
// operator session (no 429, no 400 because the Titan confirmation is now part of
// the request), and setup completion must work afterwards.
func TestFirstRunSetupFlowIsNotRateLimited(t *testing.T) {
	_, handler, gate := newSetupFlowTestServer(t)
	session := mintSession(t, handler, "setup-console", "read", "operate", "policy")
	reason := "First-run setup: operator choice after reviewed wizard recommendation"
	steps := []struct {
		path string
		body string
	}{
		{
			"/api/v1/hardening/enforce",
			`{"profile":"EnterpriseBalanced","confirmation":"APPLY HARDENING PROFILE","reason":"` + reason + `"}`,
		},
		{
			"/api/v1/integrity/configuration",
			`{"enabled":true,"intervalHours":24,"confirmation":"CHANGE INTEGRITY MONITORING","reason":"` + reason + `"}`,
		},
		{
			"/api/v1/titan/policy",
			`{"mode":"STRICT","autoQuarantine":true,"confirmation":"CHANGE TITAN POLICY","reason":"` + reason + `"}`,
		},
		{
			"/api/v1/setup/complete",
			`{"profile":"business","confirmation":"COMPLETE SETUP","reason":"First-run setup completed after verified posture."}`,
		},
	}
	for index, step := range steps {
		response := callHandler(handler, http.MethodPost, step.path, step.body, withBearer(session), withReplayID())
		if response.Code != http.StatusOK {
			t.Fatalf("setup step %d %s status=%d body=%s", index, step.path, response.Code, response.Body.String())
		}
	}
	status, err := gate.SetupStatus("5.3.0")
	if err != nil || !status.Complete {
		t.Fatalf("setup marker not persisted: %+v err=%v", status, err)
	}
}

// TestSetupBudgetDoesNotWidenGeneralLimits proves the dedicated setup budget is
// strictly scoped: after setup completes, the normal (tight) long-operation
// budget applies again to the same session.
func TestSetupBudgetDoesNotWidenGeneralLimits(t *testing.T) {
	_, handler, gate := newSetupFlowTestServer(t)
	session := mintSession(t, handler, "setup-console", "read", "operate", "policy")
	reason := "First-run setup: operator choice after reviewed wizard recommendation"
	steps := []string{
		`{"profile":"EnterpriseBalanced","confirmation":"APPLY HARDENING PROFILE","reason":"` + reason + `"}`,
		`{"enabled":true,"intervalHours":24,"confirmation":"CHANGE INTEGRITY MONITORING","reason":"` + reason + `"}`,
		`{"mode":"STRICT","autoQuarantine":true,"confirmation":"CHANGE TITAN POLICY","reason":"` + reason + `"}`,
		`{"profile":"business","confirmation":"COMPLETE SETUP","reason":"First-run setup completed after verified posture."}`,
	}
	for index, body := range steps {
		path := []string{
			"/api/v1/hardening/enforce",
			"/api/v1/integrity/configuration",
			"/api/v1/titan/policy",
			"/api/v1/setup/complete",
		}[index]
		if response := callHandler(handler, http.MethodPost, path, body, withBearer(session), withReplayID()); response.Code != http.StatusOK {
			t.Fatalf("setup step %d %s status=%d body=%s", index, path, response.Code, response.Body.String())
		}
	}
	if status, err := gate.SetupStatus("5.3.0"); err != nil || !status.Complete {
		t.Fatalf("setup marker not persisted: %+v err=%v", status, err)
	}
	// The dedicated first-run budget must be gone now; the general long budget for
	// a scoped session is two per minute, so the third request is limited again.
	for attempt := 0; attempt < 3; attempt++ {
		response := callHandler(handler, http.MethodPost, "/api/v1/hardening/enforce",
			`{"profile":"EnterpriseBalanced","confirmation":"APPLY HARDENING PROFILE","reason":"post-setup operator re-enforcement check"}`,
			withBearer(session), withReplayID())
		want := http.StatusOK
		if attempt == 2 {
			want = http.StatusTooManyRequests
		}
		if response.Code != want {
			t.Fatalf("post-setup long call %d status=%d, want %d: %s", attempt, response.Code, want, response.Body.String())
		}
	}
}

// TestSetupBudgetDoesNotApplyToOtherLongOperations proves the dedicated first-run
// class is scoped to the wizard endpoints: while setup is incomplete, an
// unrelated long operation keeps the general tight long-operation budget.
func TestSetupBudgetDoesNotApplyToOtherLongOperations(t *testing.T) {
	_, handler, gate := newSetupFlowTestServer(t)
	if status, err := gate.SetupStatus("5.3.0"); err != nil || status.Complete {
		t.Fatalf("test precondition: setup must be incomplete: %+v err=%v", status, err)
	}
	session := mintSession(t, handler, "setup-console", "read", "operate", "policy")
	for attempt := 0; attempt < 3; attempt++ {
		response := callHandler(handler, http.MethodPost, "/api/v1/health/refresh", "{}",
			withBearer(session), withReplayID())
		want := http.StatusOK
		if attempt == 2 {
			want = http.StatusTooManyRequests
		}
		if response.Code != want {
			t.Fatalf("non-setup long call %d status=%d, want %d: %s", attempt, response.Code, want, response.Body.String())
		}
	}
}

func TestLongOperationRateBudgetsDoNotCrossStarve(t *testing.T) {
	_, handler := newSecurityTestServer(t)
	session := mintSession(t, handler, "console-operator", "read", "operate", "policy")
	for _, path := range []string{"/api/v1/mhx/policy/reconcile", "/api/v1/mhx/feeds/sync", "/api/v1/health/refresh"} {
		if response := callHandler(handler, http.MethodPost, path, "{}", withBearer(session), withReplayID()); response.Code == http.StatusTooManyRequests {
			t.Fatalf("%s was starved by unrelated long operation", path)
		}
	}
	// A second sync triggered manually right after startup check must still succeed.
	if response := callHandler(handler, http.MethodPost, "/api/v1/mhx/feeds/sync", "{}", withBearer(session), withReplayID()); response.Code == http.StatusTooManyRequests {
		t.Fatalf("manual second feeds/sync was rate limited")
	}
	// A third sync on the same endpoint within one minute still trips the per-route limit.
	if response := callHandler(handler, http.MethodPost, "/api/v1/mhx/feeds/sync", "{}", withBearer(session), withReplayID()); response.Code != http.StatusTooManyRequests {
		t.Fatalf("third feeds/sync status=%d, want 429", response.Code)
	}
}

func TestSetupWizardEmbedsOfflineAgentsBlueprint(t *testing.T) {
	blueprintRaw, err := assets.ReadFile("web/agents-blueprint.js")
	if err != nil {
		t.Fatalf("missing embedded agents-blueprint.js: %v", err)
	}
	blueprint := string(blueprintRaw)
	if !strings.Contains(blueprint, "Zero Remote AI API") || !strings.Contains(blueprint, "127.0.0.1:17831") {
		t.Fatalf("agents-blueprint.js missing offline local-only invariant")
	}
	for _, forbiddenHost := range []string{"api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com"} {
		if strings.Contains(strings.ToLower(blueprint), forbiddenHost) {
			t.Fatalf("agents-blueprint.js must never reference remote AI API %s", forbiddenHost)
		}
	}
	wizardRaw, err := assets.ReadFile("web/setup-wizard.js")
	if err != nil {
		t.Fatalf("missing embedded setup-wizard.js: %v", err)
	}
	wizard := string(wizardRaw)
	for _, needle := range []string{"./agents-blueprint.js", "buildWindowsAgentsMarkdown", "openSetupWizard", "downloadAgentsBlueprint", "setupDevRoots"} {
		if !strings.Contains(wizard, needle) {
			t.Fatalf("setup-wizard.js missing %s", needle)
		}
	}
	indexRaw, err := assets.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("missing embedded index.html: %v", err)
	}
	idx := string(indexRaw)
	if !strings.Contains(idx, "systemAgentsBlueprint") || !strings.Contains(idx, "systemOpenSetupWizard") {
		t.Fatalf("index.html system page missing setup wizard / AGENTS.md controls")
	}
}
