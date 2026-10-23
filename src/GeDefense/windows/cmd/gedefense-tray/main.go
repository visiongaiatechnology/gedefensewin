// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/localhttp"
	"github.com/visiongaiatechnology/gedefense/windows/internal/operatorclient"
	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/wintray"
)

func main() {
	showVersion := flag.Bool("version", false, "show version")
	_ = flag.Bool("tray", false, "start in notification-area mode")
	openAtStart := flag.Bool("open", false, "open the security center after tray initialization")
	flag.Parse()
	if *showVersion {
		return
	}
	primary, event, mutex, tampered := claimInstance()
	if tampered {
		winapi.ReportError("tray single-instance integrity", errors.New("pre-created or unverifiable single-instance object"))
	}
	if !primary {
		if event != 0 {
			_ = winapi.SetEvent(event)
		}
		_ = winapi.CloseHandle(event)
		_ = winapi.CloseHandle(mutex)
		return
	}
	defer func() { winapi.ReportError("tray event close", winapi.CloseHandle(event)) }()
	defer func() { winapi.ReportError("tray mutex close", winapi.CloseHandle(mutex)) }()
	iconPath, err := trayIconPath()
	if err != nil {
		return
	}
	startBlockNotificationPoller()
	_ = wintray.Run(wintray.Config{
		Title:         "VGT GeDefense",
		Version:       product.Version,
		IconPath:      iconPath,
		Open:          func() { _ = startCenter() },
		Status:        protectionHealthy,
		Notifications: cachedBlockNotifications,
		OpenEvent:     uintptr(event),
		OpenAtStart:   *openAtStart,
	})
}

type controlNotification struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

var (
	blockNotificationMu    sync.Mutex
	blockNotificationCache []wintray.Notification
	toastPreferenceMu      sync.Mutex
	toastEnabled           = true
	toastMinimumSeverity   = "LOW"
	operatorSessionMu      sync.Mutex
	operatorSessionCache   operatorclient.Session
)

// acquireTraySession returns the short-lived, read-only operator session minted
// by the service after it verified this process's Windows token. The tray never
// reads the long-lived dashboard token file (UI-FIND-001 / AN-FIND-004).
func acquireTraySession() (operatorclient.Session, error) {
	operatorSessionMu.Lock()
	defer operatorSessionMu.Unlock()
	if !operatorSessionCache.Expired(time.Now()) {
		return operatorSessionCache, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := operatorclient.Acquire(ctx, operatorclient.DefaultBaseURL, operatorclient.TrayClient)
	if err != nil {
		return operatorclient.Session{}, err
	}
	operatorSessionCache = session
	return session, nil
}

func invalidateTraySession() {
	operatorSessionMu.Lock()
	operatorSessionCache = operatorclient.Session{}
	operatorSessionMu.Unlock()
}

// operatorRead performs one bounded GET with the operator read session and
// transparently re-acquires it once after a server-side rejection.
func operatorRead(path string) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		session, err := acquireTraySession()
		if err != nil {
			return nil, err
		}
		body, status, err := operatorReadOnce(session.Token, path)
		if err != nil {
			return nil, err
		}
		if status == http.StatusOK {
			return body, nil
		}
		if (status == http.StatusUnauthorized || status == http.StatusForbidden) && attempt == 0 {
			invalidateTraySession()
			continue
		}
		return nil, errors.New("control-plane rejected operator read")
	}
	return nil, errors.New("operator session rejected")
}

func operatorReadOnce(token, path string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, operatorclient.DefaultBaseURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := localhttp.NewClient(5 * time.Second).Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, response.StatusCode, errors.New("control-plane response size rejected")
	}
	return raw, response.StatusCode, nil
}

// startBlockNotificationPoller keeps a bounded cache of genuine BLOCK events.
// wintray only surfaces unseen IDs through the native notification icon, so a
// feed refresh, audit or correlation can never produce a desktop toast.
func startBlockNotificationPoller() {
	go func() {
		refreshBlockNotificationCache()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			refreshBlockNotificationCache()
		}
	}()
}

func refreshBlockNotificationCache() {
	raw, err := operatorRead("/api/v1/notifications?limit=20")
	if err != nil {
		return
	}
	var events []controlNotification
	if err := json.Unmarshal(raw, &events); err != nil {
		return
	}
	refreshToastPreferences()
	enabled, minimumSeverity := toastPreferenceSnapshot()
	next := filterBlockNotifications(events, enabled, minimumSeverity)
	blockNotificationMu.Lock()
	blockNotificationCache = next
	blockNotificationMu.Unlock()
}

func toastPreferenceSnapshot() (bool, string) {
	toastPreferenceMu.Lock()
	defer toastPreferenceMu.Unlock()
	return toastEnabled, toastMinimumSeverity
}

// refreshToastPreferences reads the operator's MHX notification policy. If the
// settings endpoint is unavailable the last known preferences remain active;
// the defaults are permissive for real blocks only.
func refreshToastPreferences() {
	raw, err := operatorRead("/api/v1/mhx/settings")
	if err != nil {
		return
	}
	var payload struct {
		Notifications struct {
			WindowsToasts        *bool  `json:"windowsToasts"`
			ToastMinimumSeverity string `json:"toastMinimumSeverity"`
		} `json:"notifications"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return
	}
	toastPreferenceMu.Lock()
	defer toastPreferenceMu.Unlock()
	if payload.Notifications.WindowsToasts != nil {
		toastEnabled = *payload.Notifications.WindowsToasts
	}
	severity := strings.ToUpper(strings.TrimSpace(payload.Notifications.ToastMinimumSeverity))
	if severityRank(severity) >= 0 {
		toastMinimumSeverity = severity
	}
}

func severityRank(value string) int {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "INFORMATIONAL":
		return 0
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	default:
		return -1
	}
}

// filterBlockNotifications keeps genuine block/containment events from the
// service's newest-first feed. Audits, feed refreshes and correlation-only
// findings must never become desktop notifications.
func filterBlockNotifications(events []controlNotification, enabled bool, minimumSeverity string) []wintray.Notification {
	next := make([]wintray.Notification, 0, len(events))
	if !enabled {
		return next
	}
	minimum := severityRank(minimumSeverity)
	if minimum < 0 {
		minimum = severityRank("LOW")
	}
	for _, event := range events {
		if (event.Kind != "BLOCK" && event.Kind != "TITAN_BLOCK") || event.ID == "" {
			continue
		}
		severity := severityRank(event.Severity)
		if severity >= 0 && severity < minimum {
			continue
		}
		next = append(next, wintray.Notification{ID: event.ID, Title: event.Title, Detail: event.Detail})
	}
	return next
}

func cachedBlockNotifications() []wintray.Notification {
	blockNotificationMu.Lock()
	defer blockNotificationMu.Unlock()
	return append([]wintray.Notification(nil), blockNotificationCache...)
}

func trayIconPath() (string, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return "", errors.New("ProgramData is unavailable")
	}
	path := filepath.Join(filepath.Clean(programData), "VGT", "Branding", "gedefense.ico")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("GeDefense tray icon unavailable")
	}
	return path, nil
}

// claimInstance establishes the tray single instance. HP-FIND-005: a named
// object that already exists is no longer sufficient reason to exit. The tray
// only delegates to another instance when the object carries the product DACL
// AND a live tray window is present; pre-created or tampered objects are
// reported and the operator UI starts anyway.
func claimInstance() (primary bool, event, mutex winapi.Handle, tampered bool) {
	eventClaim, eventErr := winapi.CreateSingleInstanceEvent("Tray.Open.v5", false, false)
	mutexClaim, mutexErr := winapi.CreateSingleInstanceMutex("Tray.Instance.v5")
	legitWindow := false
	if hwnd, err := winapi.FindGeDefenseTrayWindow(); err == nil && hwnd != 0 {
		legitWindow = true
	}
	primary, tampered = winapi.ResolveSingleInstance(mutexClaim, legitWindow, mutexErr)
	if eventErr == nil && eventClaim.Existed && !eventClaim.Trusted {
		tampered = true
	}
	return primary, eventClaim.Handle, mutexClaim.Handle, tampered
}

func startCenter() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	center := filepath.Join(filepath.Dir(executable), "GeDefenseCenter.exe")
	info, err := os.Lstat(center)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("GeDefense Center executable unavailable")
	}
	command := exec.Command(center)
	return command.Start()
}

func protectionHealthy() (healthy bool, detail string) {
	raw, err := operatorRead("/api/v1/status")
	if err != nil {
		return false, "Operatorzugriff erforderlich"
	}
	var result struct {
		Protection struct {
			Defender           bool `json:"Defender"`
			DefenderService    bool `json:"DefenderService"`
			RealTimeProtection bool `json:"RealTimeProtection"`
			CloudProtection    bool `json:"CloudProtection"`
			NetworkProtection  bool `json:"NetworkProtection"`
			Firewall           bool `json:"Firewall"`
			WindowsUpdate      bool `json:"WindowsUpdate"`
		} `json:"protection"`
		MHX struct {
			Realtime         bool   `json:"realtime"`
			ProtectionMode   string `json:"protectionMode"`
			ProtectionHealth string `json:"protectionHealth"`
		} `json:"mhx"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return false, "Status nicht verfügbar"
	}
	p := result.Protection
	coreHealthy := p.Defender && p.DefenderService && p.RealTimeProtection && p.CloudProtection && p.NetworkProtection && p.Firewall && p.WindowsUpdate && result.MHX.Realtime && result.MHX.ProtectionHealth == "VERIFIED"
	if coreHealthy && result.MHX.ProtectionMode == "sovereign" {
		return true, "Sovereign aktiv"
	}
	if coreHealthy && result.MHX.ProtectionMode == "guarded" {
		return true, "Guarded aktiv"
	}
	if result.MHX.ProtectionMode == "monitor" {
		return false, "Nur Überwachung"
	}
	if coreHealthy {
		return true, "Schutz aktiv"
	}
	return false, "Prüfung erforderlich"
}
