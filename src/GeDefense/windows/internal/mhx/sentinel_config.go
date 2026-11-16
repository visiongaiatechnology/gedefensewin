// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sentinelConfigFileName = "sentinel-config.json"
	maxSentinelConfigBytes = 64 << 10
	maxSentinelNameBytes   = 120
	maxSentinelPathBytes   = 260
	maxWhitelistEntries    = 256
	maxSentinelReasonBytes = 512

	// unsafeWildcardMigrationReason documents a FIND-WIN-009 migration that
	// deactivated a whitelist entry which authorized by file name wildcard
	// alone. The text is bounded like every other operator-facing reason and is
	// part of the persisted JSON only as an optional field.
	unsafeWildcardMigrationReason = "FIND-WIN-009: Wildcard-Whitelist ohne SHA-256-/Signer-Pin deaktiviert; Eintrag mit SHA-256- oder Signer-Pin neu anlegen"
)

type SystemAppEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

type WhitelistEntry struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	PathPattern  string    `json:"pathPattern"`
	SHA256       string    `json:"sha256,omitempty"`
	SignerMatch  string    `json:"signerMatch,omitempty"`
	Enabled      bool      `json:"enabled"`
	IsSystemApp  bool      `json:"isSystemApp"`
	AddedUTC     time.Time `json:"addedUtc"`
	LastSeenUTC  time.Time `json:"lastSeenUtc,omitempty"`
	CurrentScore int       `json:"currentScore"`
	// DisabledReason is optional (omitempty) and therefore contract-compatible
	// with older clients. It explains why an entry is currently disabled, for
	// example a legacy filename-only wildcard that the FIND-WIN-009 migration
	// deactivated because it carried no SHA-256 or signer pin.
	DisabledReason string `json:"disabledReason,omitempty"`
}

type SentinelConfig struct {
	KillerdomEnabled       bool                      `json:"killerdomEnabled"`
	ParanoiaMode           bool                      `json:"paranoiaMode"`
	CorrelateWithTitan     bool                      `json:"correlateWithTitan"`
	GhostModeTelemetryKill bool                      `json:"ghostModeTelemetryKill"`
	StrictLineageEnforced  bool                      `json:"strictLineageEnforced"`
	AmsiShieldEnforced     bool                      `json:"amsiShieldEnforced"`
	ActiveSignatures       map[string]bool           `json:"activeSignatures"`
	SystemApps             map[string]SystemAppEntry `json:"systemApps"`
	Whitelist              map[string]WhitelistEntry `json:"whitelist"`
	UpdatedUTC             time.Time                 `json:"updatedUtc"`
	Reason                 string                    `json:"reason"`
}

type SentinelStore struct {
	mu      sync.RWMutex
	ghostMu sync.Mutex
	path    string
	config  SentinelConfig
	// ghostApplied reflects the runtime state of both Ghost Mode enforcement
	// layers (hosts sinkhole + WFP-backed firewall rules). It is deliberately
	// not persisted: on every boot the OS state must be re-proven.
	ghostApplied   bool
	ghostLastError string
}

func defaultSentinelConfig() SentinelConfig {
	cfg := SentinelConfig{
		KillerdomEnabled:       true,
		ParanoiaMode:           false,
		CorrelateWithTitan:     true,
		GhostModeTelemetryKill: false,
		StrictLineageEnforced:  true,
		AmsiShieldEnforced:     true,
		ActiveSignatures:       make(map[string]bool),
		SystemApps:             make(map[string]SystemAppEntry),
		Whitelist:              make(map[string]WhitelistEntry),
		UpdatedUTC:             time.Now().UTC(),
		Reason:                 "VGT Sentinel 5.3.0 Default Baseline",
	}

	for _, sig := range killerdomSignatures {
		cfg.ActiveSignatures[sig.ID] = true
	}

	defaultSystemApps := []SystemAppEntry{
		{ID: "sys_explorer", Name: "Windows Explorer", Path: `C:\Windows\explorer.exe`, Enabled: true, Description: "Windows Shell und Dateimanager"},
		{ID: "sys_dwm", Name: "Desktop Window Manager", Path: `C:\Windows\System32\dwm.exe`, Enabled: true, Description: "Desktop Grafik- und Fenster-Manager"},
		{ID: "sys_taskmgr", Name: "Task-Manager", Path: `C:\Windows\System32\Taskmgr.exe`, Enabled: true, Description: "System-Ressourcenüberwachung"},
		{ID: "sys_services", Name: "Services Host", Path: `C:\Windows\System32\services.exe`, Enabled: true, Description: "Service Control Manager"},
		{ID: "sys_svchost", Name: "Shared Service Host", Path: `C:\Windows\System32\svchost.exe`, Enabled: true, Description: "Windows Systemdienst-Host"},
		{ID: "sys_lsass", Name: "Local Security Authority", Path: `C:\Windows\System32\lsass.exe`, Enabled: true, Description: "Sicherheits- und Authentifizierungsdienst"},
		{ID: "sys_csrss", Name: "Client-Server Runtime", Path: `C:\Windows\System32\csrss.exe`, Enabled: true, Description: "Win32 Subsystem Kernprozess"},
		{ID: "sys_cmd", Name: "Windows Eingabeaufforderung", Path: `C:\Windows\System32\cmd.exe`, Enabled: false, Description: "Kommandozeilen-Interpreter"},
		{ID: "sys_powershell", Name: "Windows PowerShell", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Enabled: false, Description: "PowerShell Host"},
	}
	for _, app := range defaultSystemApps {
		cfg.SystemApps[app.ID] = app
	}

	// FIND-WIN-009: default entries must not authorize through a bare file-name
	// wildcard. Every default entry below names an absolute canonical path; the
	// developer-tool entries that used to be enabled as "*name.exe" are shipped
	// disabled (with a visible reason) because a filename-only wildcard cannot
	// be pinned to a publisher or binary hash without knowing the install path.
	// An owner can re-add them through AddWhitelistAppPinned with a SHA-256 or
	// signer pin; the store refuses to enable an unpinned wildcard again.
	defaultWhitelist := []WhitelistEntry{
		{ID: "wl_gedefense_svc", Name: "GeDefense Service", PathPattern: `C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe`, Enabled: true, IsSystemApp: true, AddedUTC: time.Now().UTC()},
		{ID: "wl_gedefense_center", Name: "GeDefense Center", PathPattern: `C:\Program Files\VGT\GeDefense\bin\GeDefenseCenter.exe`, Enabled: true, IsSystemApp: true, AddedUTC: time.Now().UTC()},
		{ID: "wl_gedefense_tray", Name: "GeDefense Tray", PathPattern: `C:\Program Files\VGT\GeDefense\bin\GeDefenseTray.exe`, Enabled: true, IsSystemApp: true, AddedUTC: time.Now().UTC()},
		{ID: "wl_gedefense_installer", Name: "GeDefense Standalone Installer", PathPattern: `C:\Program Files\VGT\GeDefense\GeDefense-Setup.exe`, Enabled: true, IsSystemApp: true, AddedUTC: time.Now().UTC()},
		{ID: "wl_chrome", Name: "Google Chrome", PathPattern: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Enabled: true, IsSystemApp: false, AddedUTC: time.Now().UTC()},
		{ID: "wl_msedge", Name: "Microsoft Edge", PathPattern: `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, Enabled: true, IsSystemApp: false, AddedUTC: time.Now().UTC()},
		{ID: "wl_firefox", Name: "Mozilla Firefox", PathPattern: `C:\Program Files\Mozilla Firefox\firefox.exe`, Enabled: true, IsSystemApp: false, AddedUTC: time.Now().UTC()},
		{ID: "wl_antigravity", Name: "Antigravity Assistant", PathPattern: `*antigravity.exe`, Enabled: false, IsSystemApp: false, AddedUTC: time.Now().UTC(), DisabledReason: unsafeWildcardMigrationReason},
		{ID: "wl_codex", Name: "VGT Codex", PathPattern: `*codex.exe`, Enabled: false, IsSystemApp: false, AddedUTC: time.Now().UTC(), DisabledReason: unsafeWildcardMigrationReason},
		{ID: "wl_vscodium", Name: "VSCodium / VS Code", PathPattern: `*vscodium.exe`, Enabled: false, IsSystemApp: false, AddedUTC: time.Now().UTC(), DisabledReason: unsafeWildcardMigrationReason},
		{ID: "wl_code", Name: "Visual Studio Code", PathPattern: `*code.exe`, Enabled: false, IsSystemApp: false, AddedUTC: time.Now().UTC(), DisabledReason: unsafeWildcardMigrationReason},
		{ID: "wl_go", Name: "Go Toolchain", PathPattern: `*go.exe`, Enabled: false, IsSystemApp: false, AddedUTC: time.Now().UTC(), DisabledReason: unsafeWildcardMigrationReason},
		{ID: "wl_git", Name: "Git Version Control", PathPattern: `*git.exe`, Enabled: false, IsSystemApp: false, AddedUTC: time.Now().UTC(), DisabledReason: unsafeWildcardMigrationReason},
		{ID: "wl_ollama", Name: "Ollama Local AI", PathPattern: `*ollama.exe`, Enabled: false, IsSystemApp: false, AddedUTC: time.Now().UTC(), DisabledReason: unsafeWildcardMigrationReason},
	}
	for _, item := range defaultWhitelist {
		cfg.Whitelist[item.ID] = item
	}

	return cfg
}

func OpenSentinelStore(root string) (*SentinelStore, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("sentinel root must be absolute")
	}
	path := filepath.Join(root, sentinelConfigFileName)
	store := &SentinelStore{path: path}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		store.config = defaultSentinelConfig()
		if err := store.saveLocked(); err != nil {
			return nil, err
		}
		store.publishTriagePolicy()
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSentinelConfigBytes {
		return nil, errors.New("sentinel config rejected: size exceeds bound")
	}

	var loaded SentinelConfig
	if err := json.Unmarshal(raw, &loaded); err != nil {
		// A corrupt owner configuration must never be silently replaced by
		// defaults: the old bytes are preserved as forensic evidence so an
		// operator can inspect/restore the settings (whitelist, signatures,
		// ghost mode) instead of losing them without a trace.
		backupPath := fmt.Sprintf("%s.corrupt-%s", path, time.Now().UTC().Format("20060102T150405Z"))
		if writeErr := os.WriteFile(backupPath, raw, 0600); writeErr != nil {
			return nil, fmt.Errorf("sentinel config corrupt; forensic backup failed: %w", writeErr)
		}
		store.config = defaultSentinelConfig()
		store.config.Reason = "Sentinel-Konfiguration war beschädigt; Defaults geladen; Backup: " + filepath.Base(backupPath)
		if saveErr := store.saveLocked(); saveErr != nil {
			return nil, saveErr
		}
		store.publishTriagePolicy()
		return store, nil
	}
	if loaded.ActiveSignatures == nil {
		loaded.ActiveSignatures = make(map[string]bool)
	}
	if loaded.SystemApps == nil {
		loaded.SystemApps = make(map[string]SystemAppEntry)
	}
	if loaded.Whitelist == nil {
		loaded.Whitelist = make(map[string]WhitelistEntry)
	}
	modified := false
	// FIND-WIN-009 migration: older builds persisted filename-only wildcard
	// whitelist entries (for example "*code.exe") that authorized any binary
	// with a matching basename, including one in a user-writable directory.
	// Those entries are deactivated on load instead of being materialized as
	// valid; the reason stays visible for the operator and no entry is deleted.
	migratedWildcards := 0
	for id, entry := range loaded.Whitelist {
		if whitelistEntryAuthorizationSafe(entry) {
			continue
		}
		if entry.Enabled || entry.DisabledReason == "" {
			entry.Enabled = false
			entry.DisabledReason = unsafeWildcardMigrationReason
			loaded.Whitelist[id] = entry
			migratedWildcards++
			modified = true
		}
	}
	if migratedWildcards > 0 {
		note := fmt.Sprintf("%s (%d Einträge deaktiviert)", unsafeWildcardMigrationReason, migratedWildcards)
		if previous := strings.TrimSpace(loaded.Reason); previous != "" {
			note += " | " + previous
		}
		loaded.Reason = trimSentinelText(note)
	}
	// Forward-migrate the curated system-app catalog: existing installations
	// must not end up with an empty table merely because their persisted config
	// predates the 5.3.0 catalog.
	defaults := defaultSentinelConfig()
	if len(loaded.SystemApps) == 0 {
		loaded.SystemApps = defaults.SystemApps
		modified = true
	} else {
		for id, app := range defaults.SystemApps {
			if _, exists := loaded.SystemApps[id]; !exists {
				loaded.SystemApps[id] = app
				modified = true
			}
		}
	}
	// Sovereign self-protection: ensure GeDefense components are registered in
	// the whitelist and cannot stay disabled through a stale/edited config.
	geDefenseEntries := []WhitelistEntry{
		{ID: "wl_gedefense_svc", Name: "GeDefense Service", PathPattern: `C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe`, Enabled: true, IsSystemApp: true, AddedUTC: time.Now().UTC()},
		{ID: "wl_gedefense_center", Name: "GeDefense Center", PathPattern: `C:\Program Files\VGT\GeDefense\bin\GeDefenseCenter.exe`, Enabled: true, IsSystemApp: true, AddedUTC: time.Now().UTC()},
		{ID: "wl_gedefense_tray", Name: "GeDefense Tray", PathPattern: `C:\Program Files\VGT\GeDefense\bin\GeDefenseTray.exe`, Enabled: true, IsSystemApp: true, AddedUTC: time.Now().UTC()},
		{ID: "wl_gedefense_installer", Name: "GeDefense Standalone Installer", PathPattern: `C:\Program Files\VGT\GeDefense\GeDefense-Setup.exe`, Enabled: true, IsSystemApp: true, AddedUTC: time.Now().UTC()},
	}
	for _, entry := range geDefenseEntries {
		existing, exists := loaded.Whitelist[entry.ID]
		if !exists {
			loaded.Whitelist[entry.ID] = entry
			modified = true
			continue
		}
		if !existing.Enabled || !existing.IsSystemApp || existing.PathPattern != entry.PathPattern || existing.Name != entry.Name {
			existing.Enabled = true
			existing.IsSystemApp = true
			existing.PathPattern = entry.PathPattern
			existing.Name = entry.Name
			loaded.Whitelist[entry.ID] = existing
			modified = true
		}
	}
	store.config = loaded
	if modified {
		_ = store.saveLocked()
	}
	store.publishTriagePolicy()
	return store, nil
}

func (s *SentinelStore) saveLocked() error {
	s.config.UpdatedUTC = time.Now().UTC()
	payload, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return err
	}
	if len(payload) > maxSentinelConfigBytes {
		return fmt.Errorf("sentinel config exceeds %d bytes; reduce whitelist entries or shorten patterns", maxSentinelConfigBytes)
	}
	return atomicWrite(s.path, payload)
}

func (s *SentinelStore) Config() SentinelConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSentinelConfig(s.config)
}

func cloneSentinelConfig(cfg SentinelConfig) SentinelConfig {
	res := cfg
	res.ActiveSignatures = make(map[string]bool, len(cfg.ActiveSignatures))
	for k, v := range cfg.ActiveSignatures {
		res.ActiveSignatures[k] = v
	}
	res.SystemApps = make(map[string]SystemAppEntry, len(cfg.SystemApps))
	for k, v := range cfg.SystemApps {
		res.SystemApps[k] = v
	}
	res.Whitelist = make(map[string]WhitelistEntry, len(cfg.Whitelist))
	for k, v := range cfg.Whitelist {
		res.Whitelist[k] = v
	}
	return res
}

// sentinelTriagePolicy is the immutable snapshot the native process-creation
// sensor consults before it may drop an event. The sensor is started by the
// engine that owns the Sentinel store but is constructed without a store
// reference (watcher_windows.go), so the active policy is published here as a
// compact read-only view. Production runs exactly one SentinelStore per
// process; the most recently opened/updated store is authoritative.
//
// The type is deliberately detached from SentinelConfig: triage only needs the
// switches that can make an otherwise uninteresting image interesting, and the
// sensor hot path must not clone maps on every 4688 record.
type sentinelTriagePolicy struct {
	paranoia bool
	// ghostModeTelemetryKill is part of the immutable policy snapshot for
	// completeness; the sensor always forwards the curated telemetry process
	// list (fail-safe), independent of the toggle, so it cannot be used to
	// suppress an event here.
	ghostModeTelemetryKill bool
	killerdomEnabled       bool
	// activeSignatures is immutable after publication: callers must never
	// mutate the map. EvaluateKillerdomCLI only reads it.
	activeSignatures map[string]bool
}

// activeSentinelTriagePolicy is nil until a Sentinel store is opened. Triage
// treats a nil policy as "cannot prove the event is uninteresting" and
// therefore forwards the event (fail-safe toward detection).
var activeSentinelTriagePolicy atomic.Pointer[sentinelTriagePolicy]

// publishSentinelTriagePolicyFromConfig publishes the triage view for cfg. It
// copies the signature map once so readers never observe a concurrent map
// write. Tests use the same entry point to make triage deterministic.
func publishSentinelTriagePolicyFromConfig(cfg SentinelConfig) {
	signatures := make(map[string]bool, len(cfg.ActiveSignatures))
	for id, enabled := range cfg.ActiveSignatures {
		signatures[id] = enabled
	}
	activeSentinelTriagePolicy.Store(&sentinelTriagePolicy{
		paranoia:               cfg.ParanoiaMode,
		ghostModeTelemetryKill: cfg.GhostModeTelemetryKill,
		killerdomEnabled:       cfg.KillerdomEnabled,
		activeSignatures:       signatures,
	})
}

// publishTriagePolicy republishes the current config. The caller must hold
// s.mu (write lock) or exclusively own the store (OpenSentinelStore paths).
func (s *SentinelStore) publishTriagePolicy() {
	publishSentinelTriagePolicyFromConfig(s.config)
}

// currentSentinelTriagePolicy returns the active triage view. A false result
// means no Sentinel policy has been published yet.
func currentSentinelTriagePolicy() (*sentinelTriagePolicy, bool) {
	policy := activeSentinelTriagePolicy.Load()
	return policy, policy != nil
}

func (s *SentinelStore) SetParanoiaMode(enabled bool, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previousEnabled, previousReason := s.config.ParanoiaMode, s.config.Reason
	s.config.ParanoiaMode = enabled
	s.config.Reason = trimSentinelText(reason)
	if err := s.saveLocked(); err != nil {
		s.config.ParanoiaMode, s.config.Reason = previousEnabled, previousReason
		s.publishTriagePolicy()
		return err
	}
	s.publishTriagePolicy()
	return nil
}

func (s *SentinelStore) SetKillerdomEnabled(enabled bool, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previousEnabled, previousReason := s.config.KillerdomEnabled, s.config.Reason
	s.config.KillerdomEnabled = enabled
	s.config.Reason = trimSentinelText(reason)
	if err := s.saveLocked(); err != nil {
		s.config.KillerdomEnabled, s.config.Reason = previousEnabled, previousReason
		s.publishTriagePolicy()
		return err
	}
	s.publishTriagePolicy()
	return nil
}

func (s *SentinelStore) SetGhostMode(enabled bool, reason string) error {
	// Serialize all OS mutations (hosts + firewall) independently from config
	// readers so status requests never block on a slow netsh call.
	s.ghostMu.Lock()
	defer s.ghostMu.Unlock()

	s.mu.RLock()
	current := s.config.GhostModeTelemetryKill
	s.mu.RUnlock()
	if current == enabled {
		if !enabled {
			// Heal a stale sinkhole block left behind by a crashed/older build.
			if err := applyGhostModeEffects(false); err != nil {
				s.setGhostRuntime(false, err)
				return err
			}
			s.setGhostRuntime(false, nil)
		}
		return nil
	}
	// Apply the OS-level effects first. If either layer cannot be applied, the
	// config must not claim Ghost Mode is active (no decorative toggle).
	if err := applyGhostModeEffects(enabled); err != nil {
		s.setGhostRuntime(false, err)
		return fmt.Errorf("ghost mode apply: %w", err)
	}
	s.mu.Lock()
	previous := s.config.GhostModeTelemetryKill
	previousReason := s.config.Reason
	s.config.GhostModeTelemetryKill = enabled
	s.config.Reason = trimSentinelText(reason)
	if err := s.saveLocked(); err != nil {
		// Roll both OS layers and in-memory state back so config and OS state
		// never diverge.
		s.config.GhostModeTelemetryKill = previous
		s.config.Reason = previousReason
		s.publishTriagePolicy()
		s.mu.Unlock()
		_ = applyGhostModeEffects(previous)
		s.setGhostRuntime(previous, err)
		return err
	}
	s.publishTriagePolicy()
	s.mu.Unlock()
	s.setGhostRuntime(enabled, nil)
	return nil
}

// ReconcileGhostMode re-applies both Ghost Mode layers at service start when
// the persisted state says "enabled". This closes the reboot gap where Windows
// or a third party could have reset the hosts entry or firewall rules.
func (s *SentinelStore) ReconcileGhostMode() error {
	s.ghostMu.Lock()
	defer s.ghostMu.Unlock()
	s.mu.RLock()
	enabled := s.config.GhostModeTelemetryKill
	s.mu.RUnlock()
	if !enabled {
		s.setGhostRuntime(false, nil)
		return nil
	}
	if err := applyGhostModeEffects(true); err != nil {
		s.setGhostRuntime(false, err)
		return err
	}
	s.setGhostRuntime(true, nil)
	return nil
}

// GhostRuntime reports whether both enforcement layers are currently applied
// and the last apply/rollback error, if any.
func (s *SentinelStore) GhostRuntime() (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ghostApplied, s.ghostLastError
}

func (s *SentinelStore) setGhostRuntime(applied bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ghostApplied = applied
	if err != nil {
		s.ghostLastError = err.Error()
	} else {
		s.ghostLastError = ""
	}
}

func (s *SentinelStore) SetTitanCorrelation(enabled bool, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previousEnabled, previousReason := s.config.CorrelateWithTitan, s.config.Reason
	s.config.CorrelateWithTitan = enabled
	s.config.Reason = trimSentinelText(reason)
	if err := s.saveLocked(); err != nil {
		s.config.CorrelateWithTitan, s.config.Reason = previousEnabled, previousReason
		return err
	}
	return nil
}

func (s *SentinelStore) ToggleSignature(sigID string, enabled bool) error {
	sigID = strings.ToUpper(strings.TrimSpace(sigID))
	if !isKnownSignatureID(sigID) {
		return fmt.Errorf("unknown killerdom signature %q", sigID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, existed := s.config.ActiveSignatures[sigID]
	s.config.ActiveSignatures[sigID] = enabled
	if err := s.saveLocked(); err != nil {
		if existed {
			s.config.ActiveSignatures[sigID] = previous
		} else {
			delete(s.config.ActiveSignatures, sigID)
		}
		s.publishTriagePolicy()
		return err
	}
	s.publishTriagePolicy()
	return nil
}

func (s *SentinelStore) ToggleSystemApp(id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	app, found := s.config.SystemApps[id]
	if !found {
		return fmt.Errorf("system app %s not found", id)
	}
	previous := app
	app.Enabled = enabled
	s.config.SystemApps[id] = app
	if err := s.saveLocked(); err != nil {
		s.config.SystemApps[id] = previous
		return err
	}
	return nil
}

func (s *SentinelStore) ToggleWhitelistApp(id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	app, found := s.config.Whitelist[id]
	if !found {
		return fmt.Errorf("whitelist app %s not found", id)
	}
	if app.IsSystemApp {
		return fmt.Errorf("self-protection whitelist entry %s is immutable", id)
	}
	// FIND-WIN-009: re-enabling a filename-only wildcard without a SHA-256 or
	// signer pin would restore the original vulnerability, so the store refuses
	// it instead of silently authorizing arbitrary binaries by basename.
	if enabled && !whitelistEntryAuthorizationSafe(app) {
		return errors.New("whitelist wildcard entry requires a SHA-256 or signer pin before it can be enabled")
	}
	previous := app
	app.Enabled = enabled
	if enabled {
		app.DisabledReason = ""
	}
	s.config.Whitelist[id] = app
	if err := s.saveLocked(); err != nil {
		s.config.Whitelist[id] = previous
		return err
	}
	return nil
}

func (s *SentinelStore) AddWhitelistApp(name, pathPattern string) (WhitelistEntry, error) {
	return s.AddWhitelistAppPinned(name, pathPattern, "", "")
}

// AddWhitelistAppPinned creates an owner whitelist entry with optional
// SHA-256 and/or publisher pinning. Pinned entries are fail-closed: a process
// that matches the path but not the pin is not authorized.
func (s *SentinelStore) AddWhitelistAppPinned(name, pathPattern, sha256Hex, signerMatch string) (WhitelistEntry, error) {
	name = strings.TrimSpace(name)
	pathPattern = strings.TrimSpace(pathPattern)
	sha256Hex = strings.ToUpper(strings.TrimSpace(sha256Hex))
	signerMatch = strings.TrimSpace(signerMatch)
	if name == "" || pathPattern == "" {
		return WhitelistEntry{}, errors.New("name and path pattern cannot be empty")
	}
	if len(name) > maxSentinelNameBytes {
		return WhitelistEntry{}, fmt.Errorf("whitelist name exceeds %d bytes", maxSentinelNameBytes)
	}
	if err := validateWhitelistPattern(pathPattern); err != nil {
		return WhitelistEntry{}, err
	}
	// FIND-WIN-009: a wildcard pattern is only authorization-safe when it is
	// bound to a concrete binary hash or publisher. Filename-only wildcards
	// allow any binary with the matching basename (for example
	// C:\Users\Public\code.exe to inherit the VS Code trust).
	if strings.Contains(pathPattern, "*") && sha256Hex == "" && signerMatch == "" {
		return WhitelistEntry{}, errors.New("wildcard whitelist pattern requires a SHA-256 or signer pin")
	}
	if sha256Hex != "" {
		decoded, err := hex.DecodeString(sha256Hex)
		if err != nil || len(decoded) != 32 {
			return WhitelistEntry{}, errors.New("whitelist SHA-256 must be exactly 64 hex characters")
		}
	}
	if len(signerMatch) > maxSentinelNameBytes {
		return WhitelistEntry{}, fmt.Errorf("whitelist signer match exceeds %d bytes", maxSentinelNameBytes)
	}
	if strings.ContainsAny(signerMatch, "\x00\r\n") {
		return WhitelistEntry{}, errors.New("whitelist signer match contains control characters")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.config.Whitelist) >= maxWhitelistEntries {
		return WhitelistEntry{}, fmt.Errorf("whitelist capacity of %d entries reached", maxWhitelistEntries)
	}
	stamp := time.Now().UnixNano() % 1000000
	id := fmt.Sprintf("wl_custom_%d", stamp)
	for suffix := 1; ; suffix++ {
		if _, exists := s.config.Whitelist[id]; !exists {
			break
		}
		id = fmt.Sprintf("wl_custom_%d_%d", stamp, suffix)
	}
	entry := WhitelistEntry{
		ID:          id,
		Name:        name,
		PathPattern: pathPattern,
		Enabled:     true,
		IsSystemApp: false,
		AddedUTC:    time.Now().UTC(),
		SHA256:      sha256Hex,
		SignerMatch: signerMatch,
	}
	s.config.Whitelist[id] = entry
	if err := s.saveLocked(); err != nil {
		delete(s.config.Whitelist, id)
		return WhitelistEntry{}, err
	}
	return entry, nil
}

func (s *SentinelStore) RemoveWhitelistApp(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.config.Whitelist[id]
	if !found {
		return fmt.Errorf("whitelist entry %s not found", id)
	}
	if entry.IsSystemApp {
		return fmt.Errorf("self-protection whitelist entry %s is immutable", id)
	}
	delete(s.config.Whitelist, id)
	if err := s.saveLocked(); err != nil {
		s.config.Whitelist[id] = entry
		return err
	}
	return nil
}

// IsAppAllowed checks whether a running image is authorized by SystemApps or Whitelist.
//
// Security contract:
//   - curated system apps are matched by their canonical absolute image path only;
//     a foreign binary merely named "svchost.exe" or "explorer.exe" is NOT authorized;
//   - a whitelist pattern that contains a path separator must match the complete
//     image path (no basename fallback);
//   - a whitelist pattern without a path separator is matched against the basename
//     using a single-wildcard glob (*.exe / *go.exe), never as a raw substring.
func (s *SentinelStore) IsAppAllowed(imagePath string) (bool, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cleanPath := strings.ToLower(filepath.Clean(strings.TrimSpace(imagePath)))
	if cleanPath == "" || cleanPath == "." {
		return false, "", false
	}
	baseName := strings.ToLower(filepath.Base(cleanPath))

	// 1. Curated system apps: exact absolute path only.
	for _, app := range s.config.SystemApps {
		if !app.Enabled {
			continue
		}
		if cleanPath == strings.ToLower(filepath.Clean(strings.TrimSpace(app.Path))) {
			return true, app.Name, true
		}
	}

	// 2. Owner whitelist entries.
	for _, wl := range s.config.Whitelist {
		if !wl.Enabled || !whitelistEntryAuthorizationSafe(wl) {
			continue
		}
		// A pinned entry can only be evaluated with live event evidence
		// (SHA-256/signer), which this path-only helper does not have. It must
		// therefore stay fail-closed here and is only authorized through
		// IsAppAllowedEvent.
		if wl.SHA256 != "" || wl.SignerMatch != "" {
			continue
		}
		if matchSentinelPathPattern(wl.PathPattern, cleanPath, baseName) {
			return true, wl.Name, false
		}
	}

	return false, "", false
}

// IsAppAllowedEvent is the signer-aware authorization check used by the live
// process sensor. It keeps the path contract of IsAppAllowed but additionally
// refuses a curated system app whose live PE metadata proves tampering
// (renamed original image name, invalid signature, foreign publisher), and
// returns the reason so the engine can terminate with precise evidence.
func (s *SentinelStore) IsAppAllowedEvent(event ProcessEvent) (allowed bool, name string, isSystemApp bool, reason string) {
	cleanPath := strings.ToLower(filepath.Clean(strings.TrimSpace(event.ImagePath)))
	if cleanPath == "" || cleanPath == "." {
		return false, "", false, ""
	}
	baseName := strings.ToLower(filepath.Base(cleanPath))

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, app := range s.config.SystemApps {
		if !app.Enabled {
			continue
		}
		if cleanPath != strings.ToLower(filepath.Clean(strings.TrimSpace(app.Path))) {
			continue
		}
		if ok, why := verifySystemAppEvent(event); !ok {
			return false, app.Name, true, why
		}
		return true, app.Name, true, ""
	}
	for _, wl := range s.config.Whitelist {
		if !wl.Enabled {
			continue
		}
		if !matchSentinelPathPattern(wl.PathPattern, cleanPath, baseName) {
			continue
		}
		// FIND-WIN-009: a filename-only wildcard without a pin must never
		// authorize, even if a hand-edited/stale config still marks it enabled.
		if !whitelistEntryAuthorizationSafe(wl) {
			return false, wl.Name, wl.IsSystemApp, "unsafe whitelist wildcard without SHA-256/signer pin"
		}
		if wl.SHA256 != "" {
			if ok, why := verifyWhitelistSHA256Pin(wl, event); !ok {
				return false, wl.Name, wl.IsSystemApp, why
			}
		}
		if wl.SignerMatch != "" {
			if ok, why := verifyWhitelistSignerPin(wl, event); !ok {
				return false, wl.Name, wl.IsSystemApp, why
			}
		}
		if wl.IsSystemApp {
			if ok, why := verifySystemAppEvent(event); !ok {
				return false, wl.Name, true, why
			}
			return true, wl.Name, true, ""
		}
		return true, wl.Name, false, ""
	}
	return false, "", false, ""
}

// whitelistEntryAuthorizationSafe implements the FIND-WIN-009 authorization
// contract: an entry may authorize exactly when it either names a concrete
// path (no wildcard) or carries a SHA-256/signer pin. A bare filename wildcard
// ("*code.exe") is not authorization evidence because any binary with that
// basename inherits the trust.
func whitelistEntryAuthorizationSafe(entry WhitelistEntry) bool {
	if !strings.Contains(entry.PathPattern, "*") {
		return true
	}
	return strings.TrimSpace(entry.SHA256) != "" || strings.TrimSpace(entry.SignerMatch) != ""
}

// verifyWhitelistSHA256Pin enforces an owner SHA-256 pin. The live event hash is
// preferred when the sensor captured it; otherwise the image is hashed at
// verification time under the same bounded reader. A missing event hash is
// therefore never treated as a satisfied pin: an unreadable/replaced binary is
// denied.
func verifyWhitelistSHA256Pin(entry WhitelistEntry, event ProcessEvent) (bool, string) {
	pin := strings.TrimSpace(entry.SHA256)
	if pin == "" {
		return true, ""
	}
	actual := strings.TrimSpace(event.SHA256)
	if actual == "" {
		hashed, err := hashExecutableBounded(event.ImagePath)
		if err != nil {
			return false, "whitelist SHA-256 pin unverifiable"
		}
		actual = hashed
	}
	if !strings.EqualFold(actual, pin) {
		return false, "whitelist SHA-256 pin mismatch"
	}
	return true, ""
}

// verifyWhitelistSignerPin enforces an owner publisher pin. The binary must
// carry a valid Authenticode signature AND the pinned publisher string must
// appear in the signer subject or the PE CompanyName. A missing signer signal is
// fail-closed: it is not treated as a satisfied pin.
func verifyWhitelistSignerPin(entry WhitelistEntry, event ProcessEvent) (bool, string) {
	pin := strings.ToLower(strings.TrimSpace(entry.SignerMatch))
	if pin == "" {
		return true, ""
	}
	if !strings.EqualFold(strings.TrimSpace(event.SignerStatus), "Valid") {
		return false, "whitelist signer pin requires a valid Authenticode status"
	}
	for _, candidate := range []string{event.SignerSubject, event.ImageVersionCompany} {
		if candidate != "" && strings.Contains(strings.ToLower(candidate), pin) {
			return true, ""
		}
	}
	return false, "whitelist signer pin mismatch"
}

// verifySystemAppEvent validates the live PE provenance of a curated system
// app. Missing metadata is tolerated (best-effort sensor), but contradictory or
// negative evidence is fail-closed.
func verifySystemAppEvent(event ProcessEvent) (bool, string) {
	if event.SignerStatus != "" && !strings.EqualFold(event.SignerStatus, "Valid") {
		return false, "system app Authenticode status is " + event.SignerStatus
	}
	if event.OriginalImageName != "" {
		base := filepath.Base(event.ImagePath)
		if len(base) > 0 && len(event.OriginalImageName) <= 260 && !strings.EqualFold(base, event.OriginalImageName) {
			return false, "system app image was renamed (PE OriginalFilename=" + event.OriginalImageName + ")"
		}
	}
	company := strings.ToLower(strings.TrimSpace(event.ImageVersionCompany))
	if company != "" && !strings.Contains(company, "microsoft") && !strings.Contains(company, "visiongaia") {
		return false, "system app publisher is unexpected: " + event.ImageVersionCompany
	}
	return true, ""
}

func validateWhitelistPattern(pattern string) error {
	if len(pattern) > maxSentinelPathBytes {
		return fmt.Errorf("whitelist pattern exceeds %d bytes", maxSentinelPathBytes)
	}
	if strings.ContainsAny(pattern, "\x00\r\n\t") {
		return errors.New("whitelist pattern contains control characters")
	}
	if strings.ContainsAny(pattern, "?[]") {
		return errors.New("whitelist pattern only supports the '*' wildcard")
	}
	if pattern == "*" || pattern == `\*` || pattern == `*\` {
		return errors.New("whitelist pattern '*' would authorize every executable")
	}
	if strings.HasSuffix(pattern, `\`) || strings.HasSuffix(pattern, "/") {
		return errors.New("whitelist pattern must name an executable, not a directory")
	}
	if strings.Count(pattern, "*") > 2 {
		return errors.New("whitelist pattern contains too many wildcards")
	}
	normalized := strings.ReplaceAll(pattern, "/", `\`)
	normalized = strings.TrimSuffix(normalized, `\`)
	if normalized == "" || strings.Contains(normalized, `..`) {
		return errors.New("whitelist pattern must name a concrete executable")
	}
	base := normalized
	if idx := strings.LastIndex(normalized, `\`); idx >= 0 {
		base = normalized[idx+1:]
	}
	base = strings.TrimSpace(strings.ReplaceAll(base, "*", ""))
	if base == "" || base == "." || base == ".." {
		return errors.New("whitelist pattern must name a concrete executable")
	}
	return nil
}

func matchSentinelPathPattern(pattern, cleanPath, baseName string) bool {
	pat := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(pattern), "/", `\`))
	if pat == "" || pat == "*" {
		return false
	}
	if strings.Contains(pat, `\`) {
		return wildcardMatch(pat, cleanPath)
	}
	return wildcardMatch(pat, baseName)
}

// wildcardMatch implements an iterative '*' glob with O(len(pattern)+len(value))
// time and constant extra space. Both inputs MUST already be lower-cased.
func wildcardMatch(pattern, value string) bool {
	patternIdx, valueIdx := 0, 0
	starIdx, matchIdx := -1, 0
	for valueIdx < len(value) {
		if patternIdx < len(pattern) && pattern[patternIdx] == value[valueIdx] {
			patternIdx++
			valueIdx++
			continue
		}
		if patternIdx < len(pattern) && pattern[patternIdx] == '*' {
			starIdx = patternIdx
			matchIdx = valueIdx
			patternIdx++
			continue
		}
		if starIdx == -1 {
			return false
		}
		patternIdx = starIdx + 1
		matchIdx++
		valueIdx = matchIdx
	}
	for patternIdx < len(pattern) && pattern[patternIdx] == '*' {
		patternIdx++
	}
	return patternIdx == len(pattern)
}

// hashExecutableBounded hashes an image for owner SHA-256 pin verification.
// The read is streaming and bounded; a pinned entry is fail-closed when the
// file is unreadable or unreasonably large.
func hashExecutableBounded(path string) (string, error) {
	const maxPinnedExecutableBytes = 512 << 20
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, maxPinnedExecutableBytes+1))
	if err != nil {
		return "", err
	}
	if written > maxPinnedExecutableBytes {
		return "", errors.New("pinned executable exceeds hash size budget")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func trimSentinelText(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxSentinelReasonBytes {
		value = value[:maxSentinelReasonBytes]
	}
	return value
}

func isKnownSignatureID(sigID string) bool {
	for _, sig := range killerdomSignatures {
		if sig.ID == sigID {
			return true
		}
	}
	return false
}
