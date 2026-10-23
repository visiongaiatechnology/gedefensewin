// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

// writeCachedBlockingFeed plants one validated last-known-good BLOCK source so
// the real threatintel manager publishes a blocking/enforcement generation
// without any network access.
func writeCachedBlockingFeed(t *testing.T, root string) {
	t.Helper()
	indicators := []string{"45.155.205.0/24"}
	sort.Strings(indicators)
	digest := sha256.Sum256([]byte("feodo\n" + string(threatintel.ActionBlock) + "\n" + strings.Join(indicators, "\n")))
	snapshot := map[string]any{
		"schemaVersion":    threatintel.SchemaVersion,
		"key":              "feodo",
		"generatedUtc":     time.Now().UTC().Format(time.RFC3339Nano),
		"action":           string(threatintel.ActionBlock),
		"attribution":      map[string]any{"name": "Feodo Tracker C2", "url": "https://feodotracker.abuse.ch/"},
		"generationSha256": hex.EncodeToString(digest[:]),
		"indicators":       indicators,
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	sources := filepath.Join(root, "intelligence", "sources")
	if err := os.MkdirAll(sources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sources, "feodo.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

type kineticTestEngine struct {
	engine *Engine
	ledger *evidence.Ledger
}

// newKineticTestEngine builds an engine shaped like NewEngine but without
// requiring installed PowerShell script paths.
func newKineticTestEngine(t *testing.T, root string) kineticTestEngine {
	t.Helper()
	writeCachedBlockingFeed(t, root)
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	feeds, err := threatintel.NewManager(filepath.Join(root, "intelligence"))
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{root: root, ledger: ledger, feeds: feeds, kineticMonitor: kinetic.NewMonitor(), intelligenceWake: make(chan struct{}, 1), mode: "guarded"}
	engine.loadKineticState()
	return kineticTestEngine{engine: engine, ledger: ledger}
}

// satisfyKineticRequirements installs the live verified Threat-IP/WFP facts.
func (k kineticTestEngine) satisfyKineticRequirements(t *testing.T) {
	t.Helper()
	status := k.engine.feeds.Status()
	if status.EnforcementGeneration == "" || status.BlockingIndicators <= 0 {
		t.Fatalf("cached blocking feed did not produce a verified enforcement generation: %+v", status)
	}
	k.engine.mu.Lock()
	k.engine.wfpRealtime = true
	k.engine.networkRealtime = true
	k.engine.threatEnforcement = ThreatEnforcementStatus{
		State:             "VERIFIED",
		DesiredGeneration: status.EnforcementGeneration,
		ActiveGeneration:  status.EnforcementGeneration,
		Indicators:        status.BlockingIndicators,
		Rules:             4,
		Shards:            1,
		VerifiedUTC:       time.Now().UTC(),
	}
	k.engine.mu.Unlock()
}

func readPersistedKineticState(t *testing.T, root string) kineticPersistedState {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, kineticStateFileName))
	if err != nil {
		t.Fatalf("kinetic state file not written: %v", err)
	}
	var state kineticPersistedState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("kinetic state file is not valid JSON: %v", err)
	}
	return state
}

func TestKineticArmingFailsSecureWithoutVerifiedRequirements(t *testing.T) {
	test := newKineticTestEngine(t, t.TempDir())
	ctx := context.Background()
	settings := test.engine.KineticSettings()
	if settings.Armed || !settings.Observe || settings.DesiredArmed || settings.Config != kinetic.DefaultConfig() {
		t.Fatalf("new engine did not start in fail-secure observe state: %+v", settings)
	}
	if settings.Requirements.Ready || len(settings.Requirements.Blockers) == 0 {
		t.Fatalf("unverified engine advertised ready requirements: %+v", settings.Requirements)
	}
	if err := test.engine.SetKineticArmed(ctx, true); err == nil {
		t.Fatal("arming succeeded without live verified Threat-IP/WFP requirements")
	}
	if settings := test.engine.KineticSettings(); settings.Armed || settings.DesiredArmed {
		t.Fatalf("failed arming request mutated kinetic state: %+v", settings)
	}
	if _, err := os.Stat(filepath.Join(test.engine.root, kineticStateFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed arming request persisted an armed intent: %v", err)
	}
}

func TestKineticArmingPersistsIntentAndRestartReArmsOnlyAfterVerification(t *testing.T) {
	root := t.TempDir()
	first := newKineticTestEngine(t, root)
	first.satisfyKineticRequirements(t)
	if err := first.engine.SetKineticArmed(context.Background(), true); err != nil {
		t.Fatalf("verified arming request rejected: %v", err)
	}
	armed := first.engine.KineticSettings()
	if !armed.Armed || armed.Observe || !armed.DesiredArmed || armed.ArmingSource != kineticArmOperator {
		t.Fatalf("armed snapshot inconsistent: %+v", armed)
	}
	persisted := readPersistedKineticState(t, root)
	if !persisted.Armed || persisted.SchemaVersion != kineticStateSchemaVersion || persisted.Config != kinetic.DefaultConfig() {
		t.Fatalf("persisted arming intent is wrong: %+v", persisted)
	}

	// Simulated restart: persisted intent is loaded, but the engine must start
	// effectively disarmed until live requirements verify again.
	second := newKineticTestEngine(t, root)
	restarted := second.engine.KineticSettings()
	if restarted.Armed || !restarted.Observe || !restarted.DesiredArmed {
		t.Fatalf("restart trusted persisted arming instead of failing secure: %+v", restarted)
	}
	if restarted.AutoRearm.State != kineticRearmPending {
		t.Fatalf("restart did not expose a pending re-arm state: %+v", restarted.AutoRearm)
	}
	// An unavailable-TI reconciliation path must not arm and must keep a clear
	// reason plus a bounded retry timestamp.
	second.engine.reconcileKinetic(time.Now().UTC())
	pending := second.engine.KineticSettings()
	if pending.Armed || pending.AutoRearm.State != kineticRearmPending || pending.AutoRearm.NextAttemptUTC.IsZero() || pending.AutoRearm.LastError == "" {
		t.Fatalf("unverified reconcile armed or hid the retry state: %+v", pending)
	}
	firstAttempt := pending.AutoRearm.LastAttemptUTC
	second.engine.reconcileKinetic(time.Now().UTC())
	if got := second.engine.KineticSettings().AutoRearm.LastAttemptUTC; !got.Equal(firstAttempt) {
		t.Fatal("re-arm attempts were not rate limited")
	}

	// Verification returns: the persisted intent is promoted automatically.
	second.satisfyKineticRequirements(t)
	second.engine.reconcileKinetic(time.Now().UTC().Add(kineticRearmRetryInterval + time.Second))
	rearmed := second.engine.KineticSettings()
	if !rearmed.Armed || !rearmed.DesiredArmed || rearmed.AutoRearm.State != kineticRearmReArmed || rearmed.ArmingSource != kineticArmPersisted {
		t.Fatalf("verified restart did not re-arm from the persisted intent: %+v", rearmed)
	}
	if !readPersistedKineticState(t, root).Armed {
		t.Fatal("automatic re-arm erased the persisted intent")
	}
}

func TestKineticDisarmPersistsObserveAndStopsAutoRearm(t *testing.T) {
	root := t.TempDir()
	test := newKineticTestEngine(t, root)
	test.satisfyKineticRequirements(t)
	if err := test.engine.SetKineticArmed(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := test.engine.SetKineticArmed(context.Background(), false); err != nil {
		t.Fatalf("disarm failed: %v", err)
	}
	settings := test.engine.KineticSettings()
	if settings.Armed || settings.DesiredArmed || settings.AutoRearm.State != kineticRearmIdle {
		t.Fatalf("disarm snapshot inconsistent: %+v", settings)
	}
	if readPersistedKineticState(t, root).Armed {
		t.Fatal("disarm did not persist observe state")
	}
	// Even with verified requirements the engine must stay disarmed.
	test.engine.reconcileKinetic(time.Now().UTC())
	if test.engine.KineticSettings().Armed {
		t.Fatal("explicitly disarmed engine re-armed itself")
	}
}

func TestSetKineticDesiredStatePersistsIntentWhenCurrentlyUnverified(t *testing.T) {
	root := t.TempDir()
	test := newKineticTestEngine(t, root)
	snapshot, err := test.engine.SetKineticDesiredState(context.Background(), true)
	if err != nil {
		t.Fatalf("persisting the arming intent failed: %v", err)
	}
	if snapshot.Armed || !snapshot.DesiredArmed || snapshot.AutoRearm.State != kineticRearmPending {
		t.Fatalf("unverified arming intent was not reported honestly: %+v", snapshot)
	}
	if !readPersistedKineticState(t, root).Armed {
		t.Fatal("arming intent was not persisted")
	}
	if _, err := test.engine.SetKineticDesiredState(context.Background(), false); err != nil {
		t.Fatalf("clearing the intent failed: %v", err)
	}
	if readPersistedKineticState(t, root).Armed {
		t.Fatal("cleared arming intent still persisted")
	}
}

func TestKineticAutoDisarmWindowIsEnforced(t *testing.T) {
	root := t.TempDir()
	test := newKineticTestEngine(t, root)
	test.satisfyKineticRequirements(t)
	config := kinetic.DefaultConfig()
	config.AutoDisarmSeconds = kinetic.MinAutoDisarmSeconds
	if _, err := test.engine.SetKineticConfig(context.Background(), config); err != nil {
		t.Fatalf("valid auto-disarm config rejected: %v", err)
	}
	if err := test.engine.SetKineticArmed(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	// Simulate an armed window that started longer ago than configured.
	test.engine.mu.Lock()
	test.engine.kineticRuntime.armedUTC = time.Now().UTC().Add(-time.Duration(config.AutoDisarmSeconds+5) * time.Second)
	test.engine.mu.Unlock()
	test.engine.reconcileKinetic(time.Now().UTC())
	settings := test.engine.KineticSettings()
	if settings.Armed || settings.DesiredArmed {
		t.Fatalf("expired auto-disarm window was ignored: %+v", settings)
	}
	if readPersistedKineticState(t, root).Armed {
		t.Fatal("auto-disarm did not clear the persisted intent")
	}
}

func TestKineticRequirementsLossDropsArmingButKeepsPersistedIntent(t *testing.T) {
	root := t.TempDir()
	test := newKineticTestEngine(t, root)
	test.satisfyKineticRequirements(t)
	if err := test.engine.SetKineticArmed(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	test.engine.mu.Lock()
	test.engine.wfpRealtime = false
	test.engine.mu.Unlock()
	test.engine.reconcileKinetic(now)
	if !test.engine.KineticSettings().Armed {
		t.Fatal("requirements loss dropped arming without the grace period")
	}
	test.engine.reconcileKinetic(now.Add(kineticRequirementLostGrace + time.Second))
	lost := test.engine.KineticSettings()
	if lost.Armed || !lost.DesiredArmed || lost.AutoRearm.State != kineticRearmPending {
		t.Fatalf("sustained requirements loss did not drop arming fail-secure: %+v", lost)
	}
	if !readPersistedKineticState(t, root).Armed {
		t.Fatal("requirements-loss handling discarded the persisted intent")
	}
	test.engine.mu.Lock()
	test.engine.wfpRealtime = true
	test.engine.mu.Unlock()
	test.engine.reconcileKinetic(now.Add(2*kineticRequirementLostGrace + time.Second))
	if !test.engine.KineticSettings().Armed {
		t.Fatal("verified requirements did not restore automatic arming")
	}
}

func TestSetKineticConfigValidatesPersistsAndRejectsWithoutSideEffects(t *testing.T) {
	root := t.TempDir()
	test := newKineticTestEngine(t, root)
	valid := kinetic.Config{BurstWindowSeconds: 20, MinEvents: 8, MinDistinctPorts: 4, AutoDisarmSeconds: 600}
	snapshot, err := test.engine.SetKineticConfig(context.Background(), valid)
	if err != nil {
		t.Fatalf("valid kinetic config rejected: %v", err)
	}
	if snapshot.Config != valid || snapshot.ConfigSource != kineticConfigSourceStored || !snapshot.Persisted {
		t.Fatalf("valid config not reported as persisted: %+v", snapshot)
	}
	if got := test.engine.kineticMonitor.Config(); got != valid {
		t.Fatalf("monitor did not adopt the validated policy: %+v", got)
	}
	if got := readPersistedKineticState(t, root).Config; got != valid {
		t.Fatalf("persisted config mismatch: %+v", got)
	}

	invalid := valid
	invalid.MinEvents = 1
	if _, err := test.engine.SetKineticConfig(context.Background(), invalid); err == nil {
		t.Fatal("invalid kinetic config accepted")
	}
	if got := test.engine.kineticMonitor.Config(); got != valid {
		t.Fatalf("rejected config replaced the active policy: %+v", got)
	}
	if got := readPersistedKineticState(t, root).Config; got != valid {
		t.Fatalf("rejected config reached the persisted state: %+v", got)
	}
	if _, err := test.engine.SetKineticConfig(nil, valid); err == nil {
		t.Fatal("kinetic config update accepted a nil context")
	}

	// Restart reloads the persisted observation policy.
	restarted := newKineticTestEngine(t, root)
	if got := restarted.engine.KineticSettings(); got.Config != valid || got.ConfigSource != kineticConfigSourceStored {
		t.Fatalf("restart did not reload the persisted policy: %+v", got)
	}
}

func TestKineticStatePersistenceFailureNeverClaimsArming(t *testing.T) {
	root := t.TempDir()
	test := newKineticTestEngine(t, root)
	test.satisfyKineticRequirements(t)
	// Make the atomic replace target un-replaceable by turning it into a
	// directory; the write must fail and arming must not be claimed.
	statePath := filepath.Join(root, kineticStateFileName)
	if err := os.MkdirAll(filepath.Join(statePath, "blocked"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := test.engine.SetKineticArmed(context.Background(), true); err == nil {
		t.Fatal("arming reported success although state persistence failed")
	}
	if test.engine.KineticSettings().Armed {
		t.Fatal("failed persistence left the engine effectively armed")
	}
}

func TestKineticInvalidPersistedStateFallsBackToObserveDefaults(t *testing.T) {
	cases := []string{
		"not-json",
		`{"schemaVersion":0,"armed":true,"config":{"burstWindowSeconds":10,"minEvents":12,"minDistinctPorts":3,"autoDisarmSeconds":0},"updatedUtc":"2026-10-22T08:00:00Z"}`,
		`{"schemaVersion":1,"armed":true,"config":{"burstWindowSeconds":1,"minEvents":12,"minDistinctPorts":3,"autoDisarmSeconds":0},"updatedUtc":"2026-10-22T08:00:00Z"}`,
		`{"schemaVersion":1,"armed":true,"config":{"burstWindowSeconds":10,"minEvents":12,"minDistinctPorts":3,"autoDisarmSeconds":0},"updatedUtc":"2026-10-22T08:00:00Z","unknown":true}`,
		`{"schemaVersion":1,"armed":true,"config":{"burstWindowSeconds":10,"minEvents":12,"minDistinctPorts":3,"autoDisarmSeconds":0},"updatedUtc":"2026-10-22T08:00:00Z"} trailing`,
	}
	for _, body := range cases {
		root := t.TempDir()
		writeCachedBlockingFeed(t, root)
		if err := os.WriteFile(filepath.Join(root, kineticStateFileName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
		if err != nil {
			t.Fatal(err)
		}
		feeds, err := threatintel.NewManager(filepath.Join(root, "intelligence"))
		if err != nil {
			t.Fatal(err)
		}
		engine := &Engine{root: root, ledger: ledger, feeds: feeds, kineticMonitor: kinetic.NewMonitor(), mode: "guarded"}
		engine.loadKineticState()
		settings := engine.KineticSettings()
		if settings.Config != kinetic.DefaultConfig() || settings.Armed || settings.DesiredArmed {
			t.Fatalf("invalid persisted state was trusted: %+v (body %q)", settings, body)
		}
		if settings.ConfigSource != kineticConfigSourceInvalid || settings.ConfigWarning == "" {
			t.Fatalf("invalid persisted state was not surfaced: %+v", settings)
		}
	}
}

func TestKineticOperatorArmingIsIdempotentAndReportsRequirements(t *testing.T) {
	test := newKineticTestEngine(t, t.TempDir())
	test.satisfyKineticRequirements(t)
	ctx := context.Background()
	if err := test.engine.SetKineticArmed(ctx, false); err != nil {
		t.Fatalf("idempotent disarm failed: %v", err)
	}
	if err := test.engine.SetKineticArmed(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := test.engine.SetKineticArmed(ctx, true); err != nil {
		t.Fatalf("idempotent re-arm failed: %v", err)
	}
	status := test.engine.Status()
	if !status.KineticArmed || !status.KineticSettings.Armed || status.KineticSettings.Mode != "ARMED_TI_CORRELATION" {
		t.Fatalf("status did not project the armed kinetic state: %+v", status.KineticSettings)
	}
	if status.Kinetic.Mode != "ARMED_TI_CORRELATION" || status.KineticReadiness.Mode != "ARMED_TI_CORRELATION" {
		t.Fatalf("kinetic monitor/readiness mode not projected: %+v", status.Kinetic)
	}
}
