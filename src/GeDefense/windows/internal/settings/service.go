// STATUS: DIAMANT VGT SUPREME
package settings

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

// Applier is implemented by the Lead-owned policy bridge that applies a
// validated settings change to the concrete hardening/MHX/Kinetic/Threat-
// Intelligence subsystems. The settings service persists a change only after
// Apply returned nil.
type Applier interface {
	Apply(context.Context, Change) error
}

// Evidence is implemented by the tamper-evident ledger. It is optional; when
// wired, the service records the confirmed operator intent (reason digest only)
// before the applier runs. A failed preflight aborts the change.
type Evidence interface {
	Append(kind, action, result string) error
}

// Options configures the settings service.
type Options struct {
	// Path is the absolute path of the persisted settings document.
	Path string
	// Applier applies accepted changes. When nil, applies fail closed with
	// ErrUnavailable and never persist.
	Applier Applier
	// Evidence optionally records confirmed operator intent.
	Evidence Evidence
	// Clock is injectable for tests. Defaults to time.Now.
	Clock func() time.Time
}

// ChangeKind distinguishes a direct settings apply from a profile activation.
type ChangeKind string

const (
	// ChangeSettings is a direct section apply.
	ChangeSettings ChangeKind = "settings"
	// ChangeProfile is a protection profile activation.
	ChangeProfile ChangeKind = "profile"
)

// Change is the validated, bounded change handed to the Applier. Values are
// full next-value documents of every affected section, so an applier never has
// to reconstruct state from partial deltas.
type Change struct {
	Kind         ChangeKind                `json:"kind"`
	Section      string                    `json:"section,omitempty"`
	ProfileID    string                    `json:"profileId,omitempty"`
	Changed      []string                  `json:"changed"`
	Sections     map[string]map[string]any `json:"sections"`
	ReasonSHA256 string                    `json:"reasonSha256"`
	RequestedUTC time.Time                 `json:"requestedUtc"`
}

// Profile is one protection profile. Built-in profiles are code-owned and can
// never be modified or deleted.
type Profile struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description,omitempty"`
	Level       string                    `json:"level"`
	BuiltIn     bool                      `json:"builtIn"`
	UpdatedUTC  time.Time                 `json:"updatedUtc,omitempty"`
	Values      map[string]map[string]any `json:"values"`
}

// ProfileInput is the bounded create/update payload for a custom profile.
// Values may be partial: omitted controls inherit the documented defaults.
type ProfileInput struct {
	ID          string                    `json:"id,omitempty"`
	Name        string                    `json:"name"`
	Description string                    `json:"description,omitempty"`
	Level       string                    `json:"level"`
	Values      map[string]map[string]any `json:"values,omitempty"`
}

// Schema identifies the catalog/schema contract exposed by the snapshot.
type Schema struct {
	Version        int    `json:"version"`
	CatalogVersion string `json:"catalogVersion"`
}

// Snapshot is the authoritative, persisted settings view for the UI.
type Snapshot struct {
	SchemaVersion   int                       `json:"schemaVersion"`
	UpdatedUTC      time.Time                 `json:"updatedUtc,omitempty"`
	ActiveProfileID string                    `json:"activeProfileId"`
	ActiveLevel     string                    `json:"activeLevel"`
	ProtectionLevel string                    `json:"protectionLevel"`
	State           string                    `json:"state"`
	StateDetail     string                    `json:"stateDetail,omitempty"`
	ProfileDrift    bool                      `json:"profileDrift"`
	ApplierReady    bool                      `json:"applierReady"`
	Values          map[string]map[string]any `json:"values"`
	Settings        map[string]map[string]any `json:"settings"`
	Profiles        []Profile                 `json:"profiles"`
	Levels          []Level                   `json:"levels"`
	Sections        []Section                 `json:"sections"`
	Schema          Schema                    `json:"schema"`
}

// Result is returned by a successful section apply.
type Result struct {
	Applied         bool      `json:"applied"`
	Section         string    `json:"section"`
	AppliedControls []string  `json:"appliedControls"`
	UpdatedUTC      time.Time `json:"updatedUtc"`
	Snapshot        Snapshot  `json:"settings"`
}

type persistedState struct {
	SchemaVersion   int                       `json:"schemaVersion"`
	UpdatedUTC      time.Time                 `json:"updatedUtc"`
	ActiveProfileID string                    `json:"activeProfileId"`
	Profiles        []Profile                 `json:"profiles"`
	Values          map[string]map[string]any `json:"values"`
}

type stateView struct {
	activeProfileID string
	level           string
	values          map[string]map[string]any
	customProfiles  []Profile
	profiles        []Profile
	updatedUTC      time.Time
	state           string
	stateDetail     string
}

// Service is the thread-safe settings authority.
type Service struct {
	path     string
	applier  Applier
	evidence Evidence
	clock    func() time.Time

	applyMu sync.Mutex
	mu      sync.RWMutex

	activeProfileID string
	level           string
	values          map[string]map[string]any
	customProfiles  []Profile
	updatedUTC      time.Time
	state           string
	stateDetail     string
}

// Open is the convenience constructor without evidence wiring.
func Open(path string, applier Applier) (*Service, error) {
	return OpenWithOptions(Options{Path: path, Applier: applier})
}

// OpenWithOptions loads (or fails safe from) the persisted settings document.
// Only an unusable path is returned as an error; corrupt content yields a
// service in StateRecovered with documented defaults.
func OpenWithOptions(options Options) (*Service, error) {
	path := strings.TrimSpace(options.Path)
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("settings path must be absolute")
	}
	if len(path) > 4096 {
		return nil, errors.New("settings path boundary rejected")
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	service := &Service{
		path:     path,
		applier:  options.Applier,
		evidence: options.Evidence,
		clock:    clock,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("settings directory: %w", err)
	}
	service.load()
	return service, nil
}

func (service *Service) now() time.Time {
	return service.clock().UTC()
}

func (service *Service) load() {
	raw, err := readBoundedFile(service.path, maxPersistedBytes)
	if errors.Is(err, os.ErrNotExist) {
		service.installDefaults(StateDefaults, "")
		return
	}
	if err != nil {
		service.preserveRejectedFile()
		service.installDefaults(StateRecovered, "settings-file-unreadable")
		return
	}
	disk, err := decodePersistedState(raw)
	if err != nil {
		service.preserveRejectedFile()
		service.installDefaults(StateRecovered, err.Error())
		return
	}
	index := buildCatalogIndex()
	customs, err := normalizePersistedProfiles(index, disk.Profiles)
	if err != nil {
		service.preserveRejectedFile()
		service.installDefaults(StateRecovered, "settings-profile-invalid")
		return
	}
	profiles := append(builtinProfiles(), customs...)
	if _, exists := findProfile(profiles, disk.ActiveProfileID); !exists {
		service.preserveRejectedFile()
		service.installDefaults(StateRecovered, "settings-active-profile-invalid")
		return
	}
	values, err := normalizeProfileValues(index, disk.Values)
	if err != nil {
		service.preserveRejectedFile()
		service.installDefaults(StateRecovered, "settings-values-invalid")
		return
	}
	level := activeLevelFromProfiles(disk.ActiveProfileID, profiles)
	if violations := levelViolations(level, values); len(violations) > 0 {
		service.preserveRejectedFile()
		service.installDefaults(StateRecovered, "settings-invariant-violated")
		return
	}
	service.activeProfileID = disk.ActiveProfileID
	service.level = level
	service.values = values
	service.customProfiles = customs
	service.updatedUTC = disk.UpdatedUTC.UTC()
	service.state = StatePersisted
	service.stateDetail = ""
}

func (service *Service) installDefaults(state, detail string) {
	guarded, _ := builtinProfile(LevelGuarded)
	service.activeProfileID = DefaultProfileID
	service.level = LevelGuarded
	service.values = cloneValues(guarded.Values)
	service.customProfiles = nil
	service.updatedUTC = time.Time{}
	service.state = state
	service.stateDetail = detail
}

func (service *Service) preserveRejectedFile() {
	if service.path == "" {
		return
	}
	// Best-effort forensic preservation. A rejected document is never parsed
	// again; defaults stay active until an operator applies a new change.
	_ = os.Rename(service.path, service.path+".corrupt")
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	limited := io.LimitReader(file, maximum+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum {
		return nil, errors.New("settings file exceeds size boundary")
	}
	return raw, nil
}

func decodePersistedState(raw []byte) (persistedState, error) {
	var disk persistedState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&disk); err != nil {
		return persistedState{}, errors.New("settings-json-invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return persistedState{}, errors.New("settings-trailing-data-rejected")
	}
	if disk.SchemaVersion != SchemaVersion {
		return persistedState{}, errors.New("settings-schema-unsupported")
	}
	if disk.UpdatedUTC.IsZero() {
		return persistedState{}, errors.New("settings-metadata-invalid")
	}
	if len(disk.Profiles) > maxProfiles {
		return persistedState{}, errors.New("settings-profile-boundary-rejected")
	}
	return disk, nil
}

func normalizePersistedProfiles(index catalogIndex, profiles []Profile) ([]Profile, error) {
	customs := make([]Profile, 0, len(profiles))
	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		id := strings.TrimSpace(strings.ToLower(profile.ID))
		if id == "" {
			return nil, errors.New("settings profile metadata rejected")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, errors.New("settings profile duplicate rejected")
		}
		seen[id] = struct{}{}
		if _, isBuiltIn := builtinProfile(id); isBuiltIn {
			// Built-in profiles are code-owned; a persisted definition can never
			// weaken them and is therefore ignored.
			continue
		}
		normalized, err := normalizeCustomProfile(index, ProfileInput{
			ID:          profile.ID,
			Name:        profile.Name,
			Description: profile.Description,
			Level:       profile.Level,
			Values:      profile.Values,
		})
		if err != nil {
			return nil, err
		}
		if profile.UpdatedUTC.IsZero() {
			return nil, errors.New("settings profile metadata rejected")
		}
		normalized.UpdatedUTC = profile.UpdatedUTC.UTC()
		customs = append(customs, normalized)
	}
	if len(customs)+len(builtinProfiles()) > maxProfiles {
		return nil, errors.New("settings profile boundary rejected")
	}
	return customs, nil
}

func normalizeCustomProfile(index catalogIndex, input ProfileInput) (Profile, error) {
	profileID, err := normalizeProfileID(input.ID)
	if err != nil {
		return Profile{}, err
	}
	if _, builtIn := builtinProfile(profileID); builtIn {
		return Profile{}, fmt.Errorf("%w: built-in profile identifiers are reserved", ErrValidation)
	}
	name, err := normalizeProfileName(input.Name)
	if err != nil {
		return Profile{}, err
	}
	description, err := normalizeProfileDescription(input.Description)
	if err != nil {
		return Profile{}, err
	}
	level, err := normalizeProfileLevel(input.Level)
	if err != nil {
		return Profile{}, err
	}
	values, err := normalizeProfileValues(index, input.Values)
	if err != nil {
		return Profile{}, err
	}
	for rawSection, sectionValues := range input.Values {
		section, exists := index.canonicalSection(rawSection)
		if !exists {
			return Profile{}, fmt.Errorf("%w: unknown settings section", ErrValidation)
		}
		for rawKey := range sectionValues {
			key, keyErr := normalizeValueKey(section, rawKey)
			if keyErr != nil {
				return Profile{}, keyErr
			}
			control, exists := index.sectionControl(section, key)
			if !exists {
				return Profile{}, fmt.Errorf("%w: unknown control in profile", ErrValidation)
			}
			if !controlAvailableAtLevel(control, level) {
				return Profile{}, fmt.Errorf("%w: profile control is not configurable at the selected level", ErrConflict)
			}
		}
	}
	if level != LevelCustom {
		if violations := levelViolations(level, values); len(violations) > 0 {
			return Profile{}, fmt.Errorf("%w: profile cannot weaken the %s baseline: %s", ErrConflict, level, violations[0])
		}
	}
	return Profile{
		ID:          profileID,
		Name:        name,
		Description: description,
		Level:       level,
		BuiltIn:     false,
		Values:      values,
	}, nil
}

func (service *Service) currentState() stateView {
	service.mu.RLock()
	defer service.mu.RUnlock()
	profiles := append(builtinProfiles(), cloneProfiles(service.customProfiles)...)
	return stateView{
		activeProfileID: service.activeProfileID,
		level:           service.level,
		values:          cloneValues(service.values),
		customProfiles:  cloneProfiles(service.customProfiles),
		profiles:        profiles,
		updatedUTC:      service.updatedUTC,
		state:           service.state,
		stateDetail:     service.stateDetail,
	}
}

func cloneProfiles(profiles []Profile) []Profile {
	if profiles == nil {
		return nil
	}
	cloned := make([]Profile, 0, len(profiles))
	for _, profile := range profiles {
		cloned = append(cloned, Profile{
			ID:          profile.ID,
			Name:        profile.Name,
			Description: profile.Description,
			Level:       profile.Level,
			BuiltIn:     profile.BuiltIn,
			UpdatedUTC:  profile.UpdatedUTC,
			Values:      cloneValues(profile.Values),
		})
	}
	return cloned
}

// Catalog returns the static catalog contract.
func (service *Service) Catalog() Catalog {
	return CatalogDefinition()
}

// Snapshot returns the authoritative settings view.
func (service *Service) Snapshot() Snapshot {
	view := service.currentState()
	profiles := cloneProfiles(view.profiles)
	values := cloneValues(view.values)
	drift := false
	if profile, exists := findProfile(profiles, view.activeProfileID); exists {
		drift = !valuesEqual(values, profile.Values)
	}
	return Snapshot{
		SchemaVersion:   SchemaVersion,
		UpdatedUTC:      view.updatedUTC,
		ActiveProfileID: view.activeProfileID,
		ActiveLevel:     view.level,
		ProtectionLevel: view.level,
		State:           view.state,
		StateDetail:     view.stateDetail,
		ProfileDrift:    drift,
		ApplierReady:    service.applier != nil,
		Values:          values,
		Settings:        values,
		Profiles:        profiles,
		Levels:          levelDefinitions(),
		Sections:        sectionDefinitions(),
		Schema: Schema{
			Version:        SchemaVersion,
			CatalogVersion: CatalogVersion,
		},
	}
}

// Profiles returns all built-in and custom profiles.
func (service *Service) Profiles() []Profile {
	return cloneProfiles(service.currentState().profiles)
}

// Apply validates, applies and atomically persists one settings section.
func (service *Service) Apply(ctx context.Context, section string, values map[string]any, reason, confirmation string) (Result, error) {
	if err := validateRequestContext(ctx); err != nil {
		return Result{}, err
	}
	trimmedReason := strings.TrimSpace(reason)
	if err := validReason(reason); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if strings.TrimSpace(confirmation) != ConfirmationApplySettings {
		return Result{}, fmt.Errorf("%w: explicit settings confirmation required", ErrConflict)
	}
	service.applyMu.Lock()
	defer service.applyMu.Unlock()

	index := buildCatalogIndex()
	canonical, normalized, err := normalizeSectionValues(index, section, values)
	if err != nil {
		return Result{}, err
	}
	view := service.currentState()
	next := cloneValues(view.values)
	for key, value := range normalized {
		next[canonical][key] = value
	}
	for key := range normalized {
		control, _ := index.sectionControl(canonical, key)
		if !controlAvailableAtLevel(control, view.level) {
			return Result{}, fmt.Errorf("%w: control is not configurable at protection level %s", ErrConflict, view.level)
		}
	}
	if err := validateSectionSemantics(canonical, next); err != nil {
		return Result{}, err
	}
	if violations := levelViolations(view.level, next); len(violations) > 0 {
		return Result{}, fmt.Errorf("%w: protection level floor violated: %s", ErrConflict, violations[0])
	}
	change := Change{
		Kind:         ChangeSettings,
		Section:      canonical,
		Changed:      changedControlIDs(canonical, normalized),
		Sections:     map[string]map[string]any{canonical: cloneValues(next)[canonical]},
		ReasonSHA256: digestReason(trimmedReason),
		RequestedUTC: service.now(),
	}
	if service.applier == nil {
		return Result{}, fmt.Errorf("%w: no settings applier is wired", ErrUnavailable)
	}
	if err := service.preflightEvidence("settings.apply", canonical, change.ReasonSHA256); err != nil {
		return Result{}, err
	}
	if err := service.applier.Apply(ctx, change); err != nil {
		return Result{}, fmt.Errorf("%w: applier rejected settings change: %v", ErrConflict, err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("%w: request cancelled after apply", ErrUnavailable)
	}
	if err := service.commit(view.activeProfileID, next, view.customProfiles); err != nil {
		return Result{}, err
	}
	snapshot := service.Snapshot()
	return Result{
		Applied:         true,
		Section:         canonical,
		AppliedControls: change.Changed,
		UpdatedUTC:      snapshot.UpdatedUTC,
		Snapshot:        snapshot,
	}, nil
}

// CreateProfile validates and persists a new custom protection profile.
func (service *Service) CreateProfile(ctx context.Context, input ProfileInput) (Snapshot, error) {
	if err := validateRequestContext(ctx); err != nil {
		return Snapshot{}, err
	}
	service.applyMu.Lock()
	defer service.applyMu.Unlock()
	index := buildCatalogIndex()
	profile, err := normalizeCustomProfile(index, input)
	if err != nil {
		return Snapshot{}, err
	}
	view := service.currentState()
	if _, exists := findProfile(view.profiles, profile.ID); exists {
		return Snapshot{}, fmt.Errorf("%w: profile id already exists", ErrConflict)
	}
	if len(view.customProfiles)+len(builtinProfiles()) >= maxProfiles {
		return Snapshot{}, fmt.Errorf("%w: profile limit reached", ErrConflict)
	}
	profile.UpdatedUTC = service.now()
	customs := append(cloneProfiles(view.customProfiles), profile)
	if err := service.commit(view.activeProfileID, view.values, customs); err != nil {
		return Snapshot{}, err
	}
	return service.Snapshot(), nil
}

// UpdateProfile replaces the definition of an existing custom profile.
func (service *Service) UpdateProfile(ctx context.Context, id string, input ProfileInput) (Snapshot, error) {
	if err := validateRequestContext(ctx); err != nil {
		return Snapshot{}, err
	}
	service.applyMu.Lock()
	defer service.applyMu.Unlock()
	index := buildCatalogIndex()
	normalizedID, err := normalizeProfileID(id)
	if err != nil {
		return Snapshot{}, err
	}
	if _, builtIn := builtinProfile(normalizedID); builtIn {
		return Snapshot{}, fmt.Errorf("%w: built-in profiles cannot be modified", ErrConflict)
	}
	view := service.currentState()
	if _, exists := findProfile(view.customProfiles, normalizedID); !exists {
		return Snapshot{}, fmt.Errorf("%w: unknown custom profile", ErrValidation)
	}
	input.ID = normalizedID
	profile, err := normalizeCustomProfile(index, input)
	if err != nil {
		return Snapshot{}, err
	}
	profile.UpdatedUTC = service.now()
	profile.BuiltIn = false
	customs := make([]Profile, 0, len(view.customProfiles))
	for _, candidate := range view.customProfiles {
		if candidate.ID == normalizedID {
			customs = append(customs, profile)
			continue
		}
		customs = append(customs, candidate)
	}
	if err := service.commit(view.activeProfileID, view.values, customs); err != nil {
		return Snapshot{}, err
	}
	return service.Snapshot(), nil
}

// DeleteProfile removes a custom profile. Built-in, active and default profiles
// are protected.
func (service *Service) DeleteProfile(ctx context.Context, id string) (Snapshot, error) {
	if err := validateRequestContext(ctx); err != nil {
		return Snapshot{}, err
	}
	service.applyMu.Lock()
	defer service.applyMu.Unlock()
	normalizedID, err := normalizeProfileID(id)
	if err != nil {
		return Snapshot{}, err
	}
	if _, builtIn := builtinProfile(normalizedID); builtIn {
		return Snapshot{}, fmt.Errorf("%w: built-in profiles cannot be deleted", ErrConflict)
	}
	view := service.currentState()
	if _, exists := findProfile(view.customProfiles, normalizedID); !exists {
		return Snapshot{}, fmt.Errorf("%w: unknown custom profile", ErrValidation)
	}
	if normalizedID == view.activeProfileID {
		return Snapshot{}, fmt.Errorf("%w: the active profile cannot be deleted", ErrConflict)
	}
	if normalizedID == DefaultProfileID {
		return Snapshot{}, fmt.Errorf("%w: the default profile cannot be deleted", ErrConflict)
	}
	customs := make([]Profile, 0, len(view.customProfiles))
	for _, candidate := range view.customProfiles {
		if candidate.ID == normalizedID {
			continue
		}
		customs = append(customs, cloneProfiles([]Profile{candidate})[0])
	}
	if err := service.commit(view.activeProfileID, view.values, customs); err != nil {
		return Snapshot{}, err
	}
	return service.Snapshot(), nil
}

// ApplyProfile activates a profile with its explicit level confirmation phrase.
func (service *Service) ApplyProfile(ctx context.Context, id, reason, confirmation string) (Snapshot, error) {
	if err := validateRequestContext(ctx); err != nil {
		return Snapshot{}, err
	}
	if err := validReason(reason); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	normalizedID, err := normalizeProfileID(id)
	if err != nil {
		return Snapshot{}, err
	}
	service.applyMu.Lock()
	defer service.applyMu.Unlock()
	view := service.currentState()
	profile, exists := findProfile(view.profiles, normalizedID)
	if !exists {
		return Snapshot{}, fmt.Errorf("%w: unknown protection profile", ErrValidation)
	}
	expected := levelConfirmation(profile.Level)
	if expected == "" || strings.TrimSpace(confirmation) != expected {
		return Snapshot{}, fmt.Errorf("%w: explicit %s confirmation required", ErrConflict, profile.Level)
	}
	next := cloneValues(profile.Values)
	if violations := levelViolations(profile.Level, next); len(violations) > 0 {
		return Snapshot{}, fmt.Errorf("%w: profile violates its level baseline: %s", ErrConflict, violations[0])
	}
	change := Change{
		Kind:         ChangeProfile,
		ProfileID:    profile.ID,
		Changed:      changedValues(view.values, next),
		Sections:     cloneValues(next),
		ReasonSHA256: digestReason(strings.TrimSpace(reason)),
		RequestedUTC: service.now(),
	}
	if service.applier == nil {
		return Snapshot{}, fmt.Errorf("%w: no settings applier is wired", ErrUnavailable)
	}
	if err := service.preflightEvidence("settings.profile", profile.ID, change.ReasonSHA256); err != nil {
		return Snapshot{}, err
	}
	if err := service.applier.Apply(ctx, change); err != nil {
		return Snapshot{}, fmt.Errorf("%w: applier rejected profile activation: %v", ErrConflict, err)
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("%w: request cancelled after apply", ErrUnavailable)
	}
	if err := service.commit(profile.ID, next, view.customProfiles); err != nil {
		return Snapshot{}, err
	}
	return service.Snapshot(), nil
}

func validateRequestContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: request context required", ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: request cancelled", ErrUnavailable)
	}
	return nil
}

func (service *Service) preflightEvidence(kind, action, reasonDigest string) error {
	if service.evidence == nil {
		return nil
	}
	if err := service.evidence.Append(kind, action, "requested; reason-sha256="+reasonDigest); err != nil {
		return fmt.Errorf("%w: evidence preflight failed", ErrPersistence)
	}
	return nil
}

// commit writes the next state atomically and only then swaps the in-memory
// state. A failed write therefore never reports success.
func (service *Service) commit(activeProfileID string, values map[string]map[string]any, customs []Profile) error {
	now := service.now()
	persisted := persistedState{
		SchemaVersion:   SchemaVersion,
		UpdatedUTC:      now,
		ActiveProfileID: activeProfileID,
		Profiles:        persistedProfiles(customs),
		Values:          values,
	}
	payload, err := json.Marshal(persisted)
	if err != nil {
		return fmt.Errorf("%w: settings encoding failed", ErrPersistence)
	}
	payload = append(payload, '\n')
	if err := atomicWrite(service.path, payload); err != nil {
		return fmt.Errorf("%w: atomic settings commit failed", ErrPersistence)
	}
	service.mu.Lock()
	service.activeProfileID = activeProfileID
	service.values = cloneValues(values)
	service.customProfiles = cloneProfiles(customs)
	service.level = activeLevelFromProfiles(activeProfileID, append(builtinProfiles(), cloneProfiles(customs)...))
	service.updatedUTC = now
	service.state = StatePersisted
	service.stateDetail = ""
	service.mu.Unlock()
	return nil
}

func persistedProfiles(customs []Profile) []Profile {
	persisted := append(builtinProfiles(), cloneProfiles(customs)...)
	return persisted
}

func changedControlIDs(section string, changes map[string]any) []string {
	identifiers := make([]string, 0, len(changes))
	for key := range changes {
		identifiers = append(identifiers, section+"."+key)
	}
	sort.Strings(identifiers)
	return identifiers
}

func changedValues(current, next map[string]map[string]any) []string {
	changed := make([]string, 0, 16)
	for _, control := range allControls() {
		short := shortControlID(control.ID)
		if !reflect.DeepEqual(current[control.Section][short], next[control.Section][short]) {
			changed = append(changed, control.ID)
		}
	}
	sort.Strings(changed)
	return changed
}

func digestReason(reason string) string {
	digest := sha256.Sum256([]byte(reason))
	return hex.EncodeToString(digest[:])
}
