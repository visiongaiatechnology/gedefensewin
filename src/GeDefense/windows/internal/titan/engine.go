// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
)

const (
	maxEventQueue      = 512
	recentProcessLimit = 256
	remoteSessionLimit = 64
	processCorrelation = 4 * time.Second
	remoteCorrelation  = 120 * time.Second
	highRiskWindow     = 10 * time.Minute
	checkpointTicker   = 15 * time.Minute
)

type processObservation struct {
	ObservedUTC time.Time
	CreationUTC time.Time
	PID         uint32
	ParentPID   uint32
	Image       string
	Path        string
	// Chain is the observed ancestry, leaf first, bounded by the process sensor.
	Chain []string
}

type remoteObservation struct {
	ObservedUTC   time.Time
	PID           uint32
	Image         string
	RemoteAddress string
	RemotePort    uint16
	LocalPort     uint16
}

// Engine owns Titan's collection lifecycle, policy evaluation and evidence.
// It does not terminate processes and it does not claim file-to-process
// attribution that the platform sensors cannot prove.
type Engine struct {
	root    string
	version string
	policy  *PolicyStore
	journal *Journal
	vault   *Vault
	events  chan Observation

	mu               sync.RWMutex
	running          bool
	closed           bool
	startedUTC       time.Time
	sensors          map[string]SensorStatus
	watchRoots       []WatchRoot
	securityControls []SecurityControl
	boot             BootTrust
	eventsDropped    uint64
	watcherOverflows uint64
	journalVerified  bool
	lastVerification VerificationResult
	recentHighRisk   []time.Time
	notificationSeen map[string]time.Time

	processMu sync.Mutex
	processes []processObservation
	remoteMu  sync.Mutex
	remote    []remoteObservation
	sensorWG  sync.WaitGroup

	bridgeMu        sync.RWMutex
	killerdomBridge func(pid uint32, reason string) error
}

func New(root, version string, ledger *evidence.Ledger) (*Engine, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("titan root must be absolute")
	}
	if len(version) == 0 || len(version) > 64 {
		return nil, errors.New("titan version is invalid")
	}
	if err := ensurePrivateDir(root); err != nil {
		return nil, err
	}
	policy, err := OpenPolicyStore(filepath.Join(root, "policy.json"))
	if err != nil {
		return nil, err
	}
	journal, err := OpenJournal(filepath.Join(root, "evidence"), ledger)
	if err != nil {
		return nil, err
	}
	vault, err := OpenVault(filepath.Join(root, "quarantine"))
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	engine := &Engine{
		root: root, version: version, policy: policy, journal: journal, vault: vault,
		events: make(chan Observation, maxEventQueue), sensors: make(map[string]SensorStatus),
		boot:             BootTrust{Detail: "Noch keine Boot-Messung verfügbar."},
		notificationSeen: make(map[string]time.Time),
	}
	verification := journal.Verify()
	engine.journalVerified = verification.Verified
	engine.lastVerification = verification
	for _, definition := range []struct{ id, label string }{
		{"files", "Datei- und Ingress-Sensoren"},
		{"persistence", "Persistenz-Inventar"},
		{"security", "Sicherheitskonfiguration"},
		{"boot", "Boot- und Vertrauenskette"},
		{"process", "Prozesskontext"},
	} {
		engine.sensors[definition.id] = SensorStatus{ID: definition.id, Label: definition.label, State: SensorStopped}
	}
	return engine, nil
}

func (e *Engine) Version() string { return e.version }

func (e *Engine) Policy() Policy { return e.policy.Current() }

func (e *Engine) Run(stop <-chan struct{}) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.startedUTC = time.Now().UTC()
	e.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var consumer sync.WaitGroup
	consumer.Add(1)
	go func() {
		defer consumer.Done()
		e.consume(ctx)
	}()

	if err := e.startPlatformSensors(ctx); err != nil {
		e.setAllSensorsUnavailable(err.Error())
		e.appendSelfIntegrity("SENSOR_START_FAILED", err.Error(), SeverityHigh, TrustCompromised)
	}
	if e.journal.Count() > 0 {
		_, _ = e.journal.Checkpoint(true)
	}
	initialVerification := e.journal.Verify()
	e.mu.Lock()
	e.journalVerified = initialVerification.Verified
	e.lastVerification = initialVerification
	e.mu.Unlock()

	ticker := time.NewTicker(checkpointTicker)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			cancel()
			e.sensorWG.Wait()
			consumer.Wait()
			e.mu.Lock()
			e.running = false
			e.mu.Unlock()
			return
		case <-ticker.C:
			verification := e.journal.Verify()
			e.mu.Lock()
			e.lastVerification = verification
			e.journalVerified = verification.Verified
			e.mu.Unlock()
			_, _ = e.journal.Checkpoint(true)
		}
	}
}

func (e *Engine) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case observation := <-e.events:
			_ = e.record(observation)
		}
	}
}

func (e *Engine) emit(observation Observation) {
	if observation.Type == "" || observation.Source == "" {
		return
	}
	select {
	case e.events <- observation:
	default:
		e.mu.Lock()
		e.eventsDropped++
		e.mu.Unlock()
		e.markSensor("files", SensorDegraded, "Ereigniswarteschlange voll; Titan zeichnet Verluste aus.")
	}
}

func (e *Engine) record(observation Observation) error {
	now := time.Now().UTC()
	policy := e.policy.Current()
	recent := e.recentHighRiskCount(now)
	observation.Authorization = Evaluate(policy, e.policy, observation, now, recent)

	// VGT 5.3.0 Titan <-> Killerdom Correlation Bridge
	if policy.CorrelateWithKillerdom && observation.Authorization.Status == TrustCompromised {
		e.bridgeMu.RLock()
		bridge := e.killerdomBridge
		e.bridgeMu.RUnlock()
		if bridge != nil && observation.Actor.PID > 4 {
			go func(pid uint32, name, reason string) {
				if err := bridge(pid, fmt.Sprintf("Titan Correlated Strike: %s (%s)", name, reason)); err != nil {
					e.appendSelfIntegrity("KILLERDOM_BRIDGE_FAILED",
						fmt.Sprintf("Titan-Korrelation konnte PID %d nicht terminieren: %v", pid, err),
						SeverityHigh, TrustUnexpected)
				}
			}(observation.Actor.PID, observation.Object.Name, observation.Authorization.Reason)
		}
	}
	if observation.Authorization.Status == TrustUnexpected || observation.Authorization.Status == TrustCompromised {
		observation.Severity = defaultSeverity(observation.Authorization)
	} else if observation.Severity == "" {
		observation.Severity = defaultSeverity(observation.Authorization)
	}
	if observation.Response.Action == "" {
		switch {
		case observation.Authorization.AutoQuarantine:
			observation.Response = Response{Action: "QUARANTINE_PENDING", State: "PENDING"}
		case observation.Authorization.Status == TrustCompromised || observation.Authorization.Status == TrustUnexpected:
			observation.Response = Response{Action: "ALERT", State: "RECORDED"}
		default:
			observation.Response = Response{Action: "OBSERVE", State: "RECORDED"}
		}
	}
	event, err := e.journal.Append(observation)
	if err != nil {
		e.mu.Lock()
		e.journalVerified = false
		e.mu.Unlock()
		e.markSensor(sensorIDForSource(observation.Source), SensorDegraded, "Ereignis konnte nicht in die Evidenzkette geschrieben werden.")
		return err
	}
	if observation.Authorization.Status == TrustUnexpected || observation.Authorization.Status == TrustCompromised {
		e.mu.Lock()
		e.recentHighRisk = append(e.recentHighRisk, now)
		e.mu.Unlock()
	}
	e.mu.Lock()
	if len(e.recentHighRisk) > 256 {
		e.recentHighRisk = e.recentHighRisk[len(e.recentHighRisk)-256:]
	}
	e.mu.Unlock()
	if sensorID := sensorIDForSource(observation.Source); sensorID != "" {
		e.markSensor(sensorID, SensorHealthy, "")
		e.sensorEvent(sensorID)
	}
	if observation.Authorization.AutoQuarantine {
		go e.autoQuarantine(event)
	}
	return nil
}

func (e *Engine) autoQuarantine(event Event) {
	if event.Object.Kind != ObjectFile || event.Object.Path == "" {
		return
	}
	reason := "Automatische Quarantäne nach Titan-Richtlinie: unautorisierte ausführbare oder skriptfähige Datei"
	if _, err := e.quarantineEvent(event.ID, reason, "titan-policy"); err != nil {
		e.appendSelfIntegrity("AUTO_QUARANTINE_FAILED", err.Error(), SeverityHigh, TrustCompromised)
	}
}

func (e *Engine) QuarantineEvent(eventID, reason string) (QuarantineEntry, error) {
	return e.quarantineEvent(eventID, reason, "titan-owner")
}

func (e *Engine) quarantineEvent(eventID, reason, source string) (QuarantineEntry, error) {
	event, exists := e.journal.Find(eventID)
	if !exists {
		return QuarantineEntry{}, errors.New("titan event was not found")
	}
	if event.Object.Kind != ObjectFile || event.Object.Path == "" {
		return QuarantineEntry{}, errors.New("titan event has no file object to quarantine")
	}
	for _, existing := range e.vault.List() {
		if existing.EventID == event.ID && existing.State != "RESTORED" {
			return QuarantineEntry{}, errors.New("titan object is already quarantined")
		}
	}
	if event.Response.State == "QUARANTINED" {
		return QuarantineEntry{}, errors.New("titan event is already quarantined")
	}
	entry, err := e.vault.AddExpected(event.Object.Path, reason, event.ID, event.Object.SHA256)
	if err != nil {
		_, _ = e.journal.Append(Observation{
			Type: EventQuarantined, Severity: SeverityHigh,
			Object: event.Object, Actor: event.Actor, Network: event.Network,
			Authorization: Authorization{Status: TrustTolerated, RiskClass: event.Authorization.RiskClass, PolicyMode: e.policy.Current().Mode, Reason: "Titan containment action"},
			Response:      Response{Action: "QUARANTINE", State: "FAILED", Detail: err.Error()},
			Source:        source, Health: "DEGRADED", Detail: err.Error(),
		})
		return QuarantineEntry{}, err
	}
	state := "QUARANTINED"
	if !entry.OriginalGone {
		state = "QUARANTINED_ORIGINAL_PRESENT"
	}
	_, _ = e.journal.Append(Observation{
		Type: EventQuarantined, Severity: SeverityHigh,
		Object: event.Object, Actor: event.Actor, Network: event.Network,
		Authorization: Authorization{Status: TrustTolerated, RiskClass: event.Authorization.RiskClass, PolicyMode: e.policy.Current().Mode, Reason: "Titan containment action"},
		Response: Response{Action: "QUARANTINE", State: state, QuarantineID: entry.ID, OriginalGone: entry.OriginalGone,
			Detail: map[bool]string{true: "Objekt verschlüsselt isoliert.", false: "Verschlüsselte Kopie angelegt; Originaldatei blieb geöffnet oder gesperrt."}[entry.OriginalGone]},
		Source: source, Health: "HEALTHY",
	})
	return entry, nil
}

func (e *Engine) RestoreQuarantine(id, reason string) (QuarantineEntry, error) {
	entry, err := e.vault.Restore(id, reason)
	if err != nil {
		return QuarantineEntry{}, err
	}
	_, _ = e.journal.Append(Observation{
		Type: EventRestored, Severity: SeverityMedium,
		Object:        Object{Kind: ObjectFile, Path: entry.OriginalPath, Name: entry.OriginalName, SHA256: entry.SHA256, Size: entry.Size, FileType: entry.FileType},
		Authorization: Authorization{Status: TrustAuthorized, RiskClass: classifyPath(entry.OriginalPath), PolicyMode: e.policy.Current().Mode, Reason: "Besitzer-Entscheidung nach Quarantäne-Prüfung"},
		Response:      Response{Action: "RESTORE", State: "RESTORED", QuarantineID: entry.ID},
		Source:        "titan-owner", Health: "HEALTHY",
	})
	return entry, nil
}

func (e *Engine) ReviewQuarantine(id, note string) (QuarantineEntry, error) {
	entry, err := e.vault.Review(id, note)
	if err != nil {
		return QuarantineEntry{}, err
	}
	if entry.EventID != "" {
		_, _ = e.journal.MarkReviewed(entry.EventID, note)
	}
	_, _ = e.journal.Append(Observation{
		Type: EventReviewed, Severity: SeverityLow,
		Object:        Object{Kind: ObjectQuarantine, Path: "titan://quarantine/" + id, Name: id},
		Authorization: Authorization{Status: TrustTolerated, RiskClass: RiskTitan, PolicyMode: e.policy.Current().Mode, Reason: "Besitzer-Prüfung der Quarantäne"},
		Response:      Response{Action: "REVIEW", State: "RECORDED", Detail: note, QuarantineID: id},
		Source:        "titan-owner", Health: "HEALTHY", Detail: note,
	})
	return entry, nil
}

func (e *Engine) AcknowledgeEvent(eventID, note string) error {
	if _, exists := e.journal.Find(eventID); !exists {
		return errors.New("titan event was not found")
	}
	_, err := e.journal.MarkReviewed(eventID, note)
	return err
}

// AcknowledgeOpenFindings reviews a bounded page of open findings. This is an
// owner action: it does not rewrite the journal, it appends review records.
func (e *Engine) AcknowledgeOpenFindings(limit int, note string) (int, error) {
	if limit < 1 || limit > 100 {
		return 0, errors.New("titan review limit rejected")
	}
	note = strings.TrimSpace(note)
	if len(note) < 8 || len(note) > 512 {
		return 0, errors.New("titan review note boundary rejected")
	}
	reviewed := 0
	for offset := 0; ; offset += 100 {
		batch, total, err := e.journal.Recent(100, offset, FilterUnexpected)
		if err != nil {
			return reviewed, err
		}
		for _, event := range batch {
			if e.journal.Reviewed(event.ID) {
				continue
			}
			if _, err := e.journal.MarkReviewed(event.ID, note); err != nil {
				return reviewed, err
			}
			reviewed++
			if reviewed == limit {
				return reviewed, nil
			}
		}
		if offset+100 >= total {
			break
		}
	}
	return reviewed, nil
}

func (e *Engine) QuarantineEntries() []QuarantineEntry {
	return e.vault.List()
}

func (e *Engine) SetPolicy(mode string, autoQuarantine bool, reason string) (Policy, error) {
	policy, err := e.policy.SetMode(mode, autoQuarantine, reason)
	if err != nil {
		return Policy{}, err
	}
	_, _ = e.journal.Append(Observation{
		Type: EventSelfIntegrity, Severity: SeverityMedium,
		Object:        Object{Kind: ObjectSensor, Path: "titan://policy", Name: "owner-policy"},
		Authorization: Authorization{Status: TrustAuthorized, RiskClass: RiskTitan, PolicyMode: policy.Mode, Reason: "Operator-Änderung der Titan-Richtlinie"},
		Response:      Response{Action: "POLICY_UPDATE", State: "RECORDED", Detail: reason},
		Source:        "titan-owner", Health: "HEALTHY", Detail: reason,
	})
	return policy, nil
}

func (e *Engine) Permits() []Permit {
	return append([]Permit(nil), e.policy.Current().Permits...)
}

func (e *Engine) CreatePermit(path, sha256, action string, ttl time.Duration, singleUse bool, reason string) (Permit, error) {
	permit, err := e.policy.AddPermit(path, sha256, action, ttl, singleUse, reason)
	if err != nil {
		return Permit{}, err
	}
	_, _ = e.journal.Append(Observation{
		Type: EventSelfIntegrity, Severity: SeverityMedium,
		Object:        Object{Kind: ObjectSensor, Path: "titan://permit", Name: permit.ID},
		Authorization: Authorization{Status: TrustAuthorized, RiskClass: RiskTitan, PolicyMode: e.policy.Current().Mode, Reason: "Besitzer hat eine begrenzte Titan-Freigabe erteilt"},
		Response:      Response{Action: "PERMIT_CREATED", State: "RECORDED", Detail: permit.Path},
		Source:        "titan-owner", Health: "HEALTHY", Detail: reason,
	})
	return permit, nil
}

func (e *Engine) RevokePermit(id, reason string) (Policy, error) {
	policy, err := e.policy.RemovePermit(id, reason)
	if err != nil {
		return Policy{}, err
	}
	_, _ = e.journal.Append(Observation{
		Type: EventSelfIntegrity, Severity: SeverityMedium,
		Object:        Object{Kind: ObjectSensor, Path: "titan://permit", Name: id},
		Authorization: Authorization{Status: TrustAuthorized, RiskClass: RiskTitan, PolicyMode: policy.Mode, Reason: "Besitzer hat eine Titan-Freigabe widerrufen"},
		Response:      Response{Action: "PERMIT_REVOKED", State: "RECORDED", Detail: id},
		Source:        "titan-owner", Health: "HEALTHY", Detail: reason,
	})
	return policy, nil
}

func (e *Engine) SetCorrelationWithKillerdom(enabled bool, reason string) (Policy, error) {
	policy, err := e.policy.SetCorrelationWithKillerdom(enabled, reason)
	if err != nil {
		return Policy{}, err
	}
	_, _ = e.journal.Append(Observation{
		Type: EventSelfIntegrity, Severity: SeverityMedium,
		Object:        Object{Kind: ObjectSensor, Path: "titan://killerdom-bridge", Name: "killerdom-correlation"},
		Authorization: Authorization{Status: TrustAuthorized, RiskClass: RiskTitan, PolicyMode: policy.Mode, Reason: "Besitzer hat die Titan-Killerdom Fusionsbrücke aktualisiert"},
		Response:      Response{Action: "KILLERDOM_CORRELATION_UPDATED", State: "RECORDED", Detail: reason},
		Source:        "titan-owner", Health: "HEALTHY", Detail: reason,
	})
	return policy, nil
}

func (e *Engine) AddDevelopmentRoot(path, reason string) (Policy, error) {
	policy, err := e.policy.AddDevelopmentRoot(path, reason)
	if err != nil {
		return Policy{}, err
	}
	_, _ = e.journal.Append(Observation{
		Type: EventSelfIntegrity, Severity: SeverityMedium,
		Object:        Object{Kind: ObjectSensor, Path: "titan://development-root", Name: path},
		Authorization: Authorization{Status: TrustAuthorized, RiskClass: RiskTitan, PolicyMode: policy.Mode, Reason: "Besitzer hat einen Entwicklungs-/Build-Baum als solchen markiert"},
		Response:      Response{Action: "DEVELOPMENT_ROOT_ADDED", State: "RECORDED", Detail: path},
		Source:        "titan-owner", Health: "HEALTHY", Detail: reason,
	})
	return policy, nil
}

func (e *Engine) SetOwnerProcessImages(images []string, reason string) (Policy, error) {
	policy, err := e.policy.SetOwnerProcessImages(images, reason)
	if err != nil {
		return Policy{}, err
	}
	_, _ = e.journal.Append(Observation{
		Type: EventSelfIntegrity, Severity: SeverityMedium,
		Object:        Object{Kind: ObjectSensor, Path: "titan://owner-process-images", Name: "owner-toolchain"},
		Authorization: Authorization{Status: TrustAuthorized, RiskClass: RiskTitan, PolicyMode: policy.Mode, Reason: "Besitzer hat die Entwickler-Toolchain für Ingress-Evidenz freigegeben"},
		Response:      Response{Action: "OWNER_PROCESS_IMAGES_UPDATED", State: "RECORDED", Detail: reason},
		Source:        "titan-owner", Health: "HEALTHY", Detail: reason,
	})
	return policy, nil
}

func (e *Engine) RemoveDevelopmentRoot(path, reason string) (Policy, error) {
	policy, err := e.policy.RemoveDevelopmentRoot(path, reason)
	if err != nil {
		return Policy{}, err
	}
	_, _ = e.journal.Append(Observation{
		Type: EventSelfIntegrity, Severity: SeverityMedium,
		Object:        Object{Kind: ObjectSensor, Path: "titan://development-root", Name: path},
		Authorization: Authorization{Status: TrustAuthorized, RiskClass: RiskTitan, PolicyMode: policy.Mode, Reason: "Besitzer hat die Entwicklungsbaum-Markierung entfernt"},
		Response:      Response{Action: "DEVELOPMENT_ROOT_REMOVED", State: "RECORDED", Detail: path},
		Source:        "titan-owner", Health: "HEALTHY", Detail: reason,
	})
	return policy, nil
}

func (e *Engine) Events(limit, offset int, filter EventFilter) ([]Event, int, error) {
	return e.journal.Recent(limit, offset, filter)
}

// Notifications exposes only high-signal findings to the owner-facing feed.
// Local UI toasts are not treated as an independent channel.
func (e *Engine) Notifications(limit int) []Notification {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	window := limit * 2
	if window > 100 {
		window = 100
	}
	events, _, err := e.journal.Recent(window, 0, FilterAll)
	if err != nil {
		return []Notification{}
	}
	result := make([]Notification, 0, limit)
	for _, event := range events {
		var notification Notification
		switch event.Type {
		case EventQuarantined:
			notification = Notification{ID: event.ID, TimestampUTC: event.TimestampUTC, Kind: "TITAN_BLOCK",
				Severity: SeverityHigh, Title: "Titan: Objekt isoliert",
				Detail: fmt.Sprintf("%s · %s", event.Object.Name, event.Response.State)}
		case EventRestored:
			notification = Notification{ID: event.ID, TimestampUTC: event.TimestampUTC, Kind: "TITAN",
				Severity: SeverityMedium, Title: "Titan: Objekt wiederhergestellt",
				Detail: event.Object.Name}
		default:
			if event.Authorization.Status != TrustUnexpected && event.Authorization.Status != TrustCompromised {
				continue
			}
			if e.journal.Reviewed(event.ID) {
				continue
			}
			if !e.notificationAllowed(event) {
				continue
			}
			kind := "TITAN"
			if event.Severity == SeverityHigh || event.Severity == SeverityCritical {
				kind = "TITAN_BLOCK"
			}
			notification = Notification{ID: event.ID, TimestampUTC: event.TimestampUTC, Kind: kind,
				Severity: event.Severity, Title: "Titan: unautorisierte Systemänderung",
				Detail: fmt.Sprintf("%s · %s", event.Object.Name, event.Authorization.Status)}
		}
		if notification.ID == "" || notification.TimestampUTC.IsZero() {
			continue
		}
		result = append(result, notification)
		if len(result) == limit {
			break
		}
	}
	return result
}

func (e *Engine) notificationAllowed(event Event) bool {
	key := string(event.Authorization.Status) + "|" + event.Collection.Source + "|" + event.Object.Path + "|" + event.Object.Name
	now := time.Now().UTC()
	e.mu.Lock()
	defer e.mu.Unlock()
	if last, seen := e.notificationSeen[key]; seen && now.Sub(last) < 10*time.Minute {
		return false
	}
	if len(e.notificationSeen) > 2048 {
		for staleKey, stamp := range e.notificationSeen {
			if now.Sub(stamp) > 30*time.Minute {
				delete(e.notificationSeen, staleKey)
			}
		}
	}
	e.notificationSeen[key] = now
	return true
}

func (e *Engine) Checkpoints(limit int) []Checkpoint { return e.journal.Checkpoints(limit) }

func (e *Engine) Verify() VerificationResult {
	result := e.journal.Verify()
	e.mu.Lock()
	e.lastVerification = result
	e.journalVerified = result.Verified
	e.mu.Unlock()
	return result
}

func (e *Engine) Export(limit int) (EvidenceBundle, error) {
	bundle, verification, err := e.journal.Export(limit)
	if err != nil {
		return EvidenceBundle{}, err
	}
	if !verification.Verified {
		return EvidenceBundle{}, errors.New("titan evidence does not verify; export refused")
	}
	return bundle, nil
}

func (e *Engine) Status() Status {
	policy := e.policy.Current()
	journalStatus := e.journal.Status()
	e.mu.Lock()
	sensors := make([]SensorStatus, 0, len(e.sensors))
	for _, sensor := range e.sensors {
		sensors = append(sensors, sensor)
	}
	watchRoots := append([]WatchRoot(nil), e.watchRoots...)
	security := append([]SecurityControl(nil), e.securityControls...)
	boot := e.boot
	started := e.startedUTC
	running := e.running
	dropped := e.eventsDropped
	overflows := e.watcherOverflows
	verification := e.lastVerification
	e.mu.Unlock()
	sort.Slice(sensors, func(left, right int) bool { return sensors[left].ID < sensors[right].ID })

	state := "STOPPED"
	if running {
		state = "OBSERVING"
		if policy.Mode != ModeObserve {
			state = "PROTECTING"
		}
	}
	degraded := false
	for _, sensor := range sensors {
		if sensor.State == SensorDegraded || sensor.State == SensorUnavailable {
			degraded = true
			break
		}
	}
	if !verification.Verified || e.journal.Error() != "" || dropped > 0 || overflows > 0 {
		degraded = true
	}
	if degraded {
		state = "DEGRADED"
	}
	uptime := int64(0)
	if !started.IsZero() {
		uptime = int64(time.Since(started).Seconds())
	}
	quarantineEntriesCount, quarantineBytes := e.vault.Usage()
	maxEntries, maxBytes, diskReserve := e.vault.Limits()
	return Status{
		Version: e.version, State: state, TrustPosture: e.journal.Posture(), Mode: policy.Mode,
		StartedUTC: started, UptimeSeconds: uptime, Sensors: sensors,
		EventCount: e.journal.Count(), OpenFindings: e.journal.OpenFindings(), QuarantineCount: quarantineEntriesCount,
		LastEventUTC: e.journal.LastEventUTC(), LastCheckpoint: journalStatus,
		JournalVerified: verification.Verified, JournalError: e.journal.Error(),
		Policy: policy, WatchRoots: watchRoots, SecurityControls: security, Boot: boot,
		Witness: WitnessStatus{Configured: false, Reachable: false,
			LastCheckpointUTC: journalStatus.CreatedUTC,
			Detail:            "Kein unabhängiger Witness konfiguriert. Checkpoints sind lokal signiert; das ist manipulationsanzeigend, aber kein externer Vertrauensanker."},
		EventsDropped: dropped, WatcherOverflows: overflows, QuarantineBytes: quarantineBytes, CanQuarantine: true,
		Limits: Limits{
			MaxEventsPerPage: 100, MaxQuarantineMB: maxQuarantineFileBytes >> 20, MaxPermits: maxPermits,
			MaxQuarantineEntries: maxEntries, MaxQuarantineTotalMB: int(maxBytes >> 20),
			MinDiskReserveMB: int(diskReserve >> 20),
		},
	}
}

func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()
	var checkpointErr error
	if e.journal.Count() > 0 {
		_, checkpointErr = e.journal.Checkpoint(true)
	}
	closeErr := e.journal.Close()
	return errors.Join(checkpointErr, closeErr)
}

func (e *Engine) setAllSensorsUnavailable(detail string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, sensor := range e.sensors {
		sensor.State = SensorUnavailable
		sensor.Detail = detail
		e.sensors[id] = sensor
	}
}

func (e *Engine) markSensor(id string, state SensorState, detail string) {
	if id == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	sensor, exists := e.sensors[id]
	if !exists {
		sensor = SensorStatus{ID: id, Label: id}
	}
	sensor.State = state
	sensor.Detail = detail
	if state == SensorDegraded || state == SensorUnavailable {
		sensor.Errors++
	}
	e.sensors[id] = sensor
}

func (e *Engine) sensorEvent(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	sensor, exists := e.sensors[id]
	if !exists {
		sensor = SensorStatus{ID: id, Label: id}
	}
	sensor.Events++
	sensor.LastEventUTC = time.Now().UTC()
	e.sensors[id] = sensor
}

func (e *Engine) setWatchRoots(roots []WatchRoot) {
	e.mu.Lock()
	e.watchRoots = append([]WatchRoot(nil), roots...)
	e.mu.Unlock()
}

func (e *Engine) setSecurityControls(controls []SecurityControl) {
	e.mu.Lock()
	e.securityControls = append([]SecurityControl(nil), controls...)
	e.mu.Unlock()
}

func (e *Engine) setBootTrust(boot BootTrust) {
	e.mu.Lock()
	e.boot = boot
	e.mu.Unlock()
}

func (e *Engine) setWatcherOverflows(count uint64) {
	e.mu.Lock()
	e.watcherOverflows += count
	e.mu.Unlock()
}

func (e *Engine) processContext(now time.Time) (Actor, bool) {
	e.processMu.Lock()
	defer e.processMu.Unlock()
	for index := len(e.processes) - 1; index >= 0; index-- {
		process := e.processes[index]
		distance := now.Sub(process.ObservedUTC)
		if distance < 0 || distance > processCorrelation {
			continue
		}
		// conhost.exe is a console host, not the process that performed a file
		// operation. Returning it as the actor produces misleading attribution and
		// was the largest single source of Titan false positives. Prefer the next
		// observed process; if none exists, report an honest NONE actor.
		if strings.EqualFold(process.Image, "conhost.exe") || strings.EqualFold(process.Image, "audiodg.exe") {
			continue
		}
		return Actor{PID: process.PID, ParentPID: process.ParentPID, Image: process.Image, Path: process.Path,
			ProcessChain:        append([]string(nil), process.Chain...),
			CorrelationQuality:  CorrelationTemporal,
			CorrelationNote:     "Prozessstart zeitlich nahe der Dateiänderung; keine Datei-zu-PID-Zuordnung beobachtet.",
			ObservedProcessTime: process.ObservedUTC}, true
	}
	return Actor{CorrelationQuality: CorrelationNone, CorrelationNote: "Keine direkte oder zeitlich nahe Prozesszuordnung beobachtet."}, false
}

func (e *Engine) networkContext(now time.Time) (NetworkContext, bool) {
	e.remoteMu.Lock()
	defer e.remoteMu.Unlock()
	for index := len(e.remote) - 1; index >= 0; index-- {
		remote := e.remote[index]
		distance := now.Sub(remote.ObservedUTC)
		if distance < 0 || distance > remoteCorrelation {
			continue
		}
		return NetworkContext{CorrelationQuality: CorrelationTemporal, RemoteAddress: remote.RemoteAddress,
			RemotePort: remote.RemotePort, LocalPort: remote.LocalPort, Image: remote.Image,
			Detail: "Fernverbindung wurde zeitlich im selben Beobachtungsfenster gesehen; kein Datenfluss dieser Verbindung zur Datei belegt."}, true
	}
	return NetworkContext{CorrelationQuality: CorrelationNone}, false
}

func (e *Engine) observeProcesses(processes []processObservation) {
	if len(processes) == 0 {
		return
	}
	e.processMu.Lock()
	e.processes = append(e.processes, processes...)
	if len(e.processes) > recentProcessLimit {
		copy(e.processes, e.processes[len(e.processes)-recentProcessLimit:])
		e.processes = e.processes[:recentProcessLimit]
	}
	e.processMu.Unlock()
}

func (e *Engine) observeRemote(remote remoteObservation) {
	e.remoteMu.Lock()
	e.remote = append(e.remote, remote)
	if len(e.remote) > remoteSessionLimit {
		copy(e.remote, e.remote[len(e.remote)-remoteSessionLimit:])
		e.remote = e.remote[:remoteSessionLimit]
	}
	e.remoteMu.Unlock()
}

func (e *Engine) recentHighRiskCount(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := now.Add(-highRiskWindow)
	kept := e.recentHighRisk[:0]
	for _, timestamp := range e.recentHighRisk {
		if timestamp.After(cutoff) && !timestamp.After(now) {
			kept = append(kept, timestamp)
		}
	}
	e.recentHighRisk = kept
	return len(kept)
}

func (e *Engine) appendSelfIntegrity(action, detail string, severity Severity, trust TrustStatus) {
	_, _ = e.journal.Append(Observation{
		Type: EventSelfIntegrity, Severity: severity,
		Object:        Object{Kind: ObjectSensor, Path: "titan://self", Name: action},
		Authorization: Authorization{Status: trust, RiskClass: RiskTitan, PolicyMode: e.policy.Current().Mode, Reason: detail},
		Response:      Response{Action: action, State: "RECORDED", Detail: detail},
		Source:        "titan-self", Health: "DEGRADED", Detail: detail,
	})
}

func defaultSeverity(authorization Authorization) Severity {
	switch authorization.Status {
	case TrustCompromised:
		return SeverityCritical
	case TrustUnexpected:
		switch authorization.RiskClass {
		case RiskSecurity, RiskBoot:
			return SeverityCritical
		case RiskPersistence, RiskSystem:
			return SeverityHigh
		case RiskIngress:
			if authorization.RiskScore >= 50 {
				return SeverityHigh
			}
			return SeverityMedium
		default:
			return SeverityMedium
		}
	default:
		if authorization.RiskScore >= 35 {
			return SeverityMedium
		}
		return SeverityLow
	}
}

func sensorIDForSource(source string) string {
	switch source {
	case "titan-file-watch":
		return "files"
	case "titan-persistence":
		return "persistence"
	case "titan-security":
		return "security"
	case "titan-boot":
		return "boot"
	case "titan-process":
		return "process"
	default:
		return ""
	}
}

// SetKillerdomBridge registers the kinetic callback used to terminate processes
// identified by Titan as responsible for high-risk system compromise.
func (e *Engine) SetKillerdomBridge(bridge func(pid uint32, reason string) error) {
	e.bridgeMu.Lock()
	defer e.bridgeMu.Unlock()
	e.killerdomBridge = bridge
}
