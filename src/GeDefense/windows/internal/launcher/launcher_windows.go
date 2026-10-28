// STATUS: PLATIN
//go:build windows

package launcher

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/cleanup"
	"github.com/visiongaiatechnology/gedefense/windows/internal/localhttp"
	"github.com/visiongaiatechnology/gedefense/windows/internal/operatorclient"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winframe"
)

const (
	controlPlaneBaseURL = "http://127.0.0.1:17831"
	controlPlaneURL     = controlPlaneBaseURL + "/"
	centerClientName    = "center"
	launcherClientName  = "center-launcher"

	// browserAttachDeadline bounds how long the launcher waits for the
	// Chromium browser to expose its own top-level window after process start.
	// Cold starts with device attestation, antivirus scanning or a pending
	// browser update regularly exceed the former 15 s on managed endpoints.
	browserAttachDeadline = 45 * time.Second
)

// FailureKind classifies why the Center window could not be opened, so the
// Center can present a specific German cause instead of one opaque error box.
type FailureKind string

const (
	// FailureBroker means the local operator handshake was rejected or the
	// control-plane service was unreachable.
	FailureBroker FailureKind = "broker"
	// FailureBrowser means no trusted, code-signed Chromium browser was found.
	FailureBrowser FailureKind = "browser"
	// FailureHost means the native window host could not be created or used.
	FailureHost FailureKind = "host"
	// FailureStartup means the browser process failed to start or failed to
	// expose its window within the attach deadline.
	FailureStartup FailureKind = "startup"
	// FailureProfile means the throw-away browser profile could not be created.
	FailureProfile FailureKind = "profile"
	// FailureElevation documents that the unprivileged hand-over failed and the
	// UI kept running elevated as a diagnostic fallback.
	FailureElevation FailureKind = "elevation"
)

// Failure wraps a launch error with its diagnostic category while keeping the
// original error available through errors.Is/errors.As.
type Failure struct {
	Kind FailureKind
	Err  error
}

func (f *Failure) Error() string {
	if f.Err == nil {
		return string(f.Kind)
	}
	return string(f.Kind) + ": " + f.Err.Error()
}

// Unwrap exposes the underlying error to errors.Is/errors.As.
func (f *Failure) Unwrap() error { return f.Err }

func failure(kind FailureKind, err error) error {
	if err == nil {
		return nil
	}
	return &Failure{Kind: kind, Err: err}
}

// KindOf reports the diagnostic category of err, or "" when err carries none.
func KindOf(err error) FailureKind {
	var target *Failure
	if errors.As(err, &target) {
		return target.Kind
	}
	return ""
}

// Describe maps a launch failure to a specific German cause summary and an
// actionable remediation hint for the Center's error dialog. The texts are
// deliberately bounded: they are shown in a native message box and never
// contain credentials or server responses.
func Describe(err error) (summary, hint string) {
	switch KindOf(err) {
	case FailureBroker:
		return "Der lokale GeDefense-Dienst hat die Operator-Anmeldung abgelehnt oder war nicht erreichbar.",
			"Prüfen Sie, ob der GeDefense-Dienst läuft, und starten Sie das Center erneut."
	case FailureBrowser:
		return "Es wurde kein signierter Chromium-Browser gefunden.",
			"Installieren oder reparieren Sie Microsoft Edge, Google Chrome oder Brave unter Program Files."
	case FailureHost:
		return "Das native Center-Fenster konnte nicht erstellt werden.",
			"Schließen Sie ein bereits geöffnetes Center-Fenster und starten Sie das Center erneut."
	case FailureStartup:
		return "Der Browserprozess für das Center wurde nicht rechtzeitig bereit.",
			"Prüfen Sie, ob ein Browser-Update oder eine Sicherheitsrichtlinie den Browserstart blockiert."
	case FailureProfile:
		return "Das temporäre Center-Profil konnte nicht angelegt werden.",
			"Prüfen Sie die Schreibrechte unter %LocalAppData%\\VGT\\GeDefense."
	case FailureElevation:
		return "Der unprivilegierte Start über die Desktop-Shell ist fehlgeschlagen; das Center läuft weiterhin mit Administratorrechten.",
			"Starten Sie GeDefense Center ohne \"Als Administrator ausführen\" über Startmenü oder Taskleiste."
	default:
		return "Das Center konnte wegen eines unerwarteten Fehlers nicht geöffnet werden.",
			"Starten Sie das Center erneut; bleibt der Fehler bestehen, prüfen Sie das Diagnoseprotokoll."
	}
}

// SECURITY LIMITATION (UI-FIND-002, explicit, not an embedded-host claim):
// The Center host is NOT an embedded native renderer application. It
// launches an externally installed Chromium browser in kiosk mode inside a
// dedicated profile and reparents that browser window into a native Win32 host.
// Therefore this product cannot enforce DevTools, navigation, context menu,
// download or permission policy inside the renderer. The mitigations that are
// enforced here:
//   - only a fixed, administrator-writable browser path under %ProgramFiles% /
//     %ProgramFiles(x86)% is accepted (no %LocalAppData%, no HKCU App Paths),
//   - every path component must be a regular directory/file (reparse points are
//     rejected) so a per-user junction cannot redirect the launch,
//   - the browser command line carries the plain loopback URL only; the session
//     bootstrap is bound server-side to the launched browser process (AN-FIND-002),
//   - the browser runs in a fresh throw-away profile without extensions/sync.
//
// Residual risk: the browser vendor's version/policy and its renderer isolation
// are outside this product's control. A native embedded renderer host would be
// required to claim host-enforced kiosk controls.
func Open() error {
	return openDedicatedWindow()
}

func openDedicatedWindow() (err error) {
	elevated := winapi.IsProcessElevated()
	browserPath := ""
	// One diagnostic record per launch attempt, including successful ones: the
	// Center log is the evidence trail when an operator reports a launch problem.
	defer func() {
		recordLaunchDiagnostic(launchDiagnostic{
			Category: diagnosticCategory(err),
			Elevated: elevated,
			Browser:  browserPath,
			Detail:   diagnosticDetail(err),
		})
	}()
	// The window host no longer reads the long-lived dashboard token file. It
	// asks the service for a short-lived operator session; the service verifies
	// this process's Windows token (operator group / Administrators) via the
	// loopback peer (UI-FIND-001 / AN-FIND-004).
	session, err := operatorclient.Acquire(context.Background(), controlPlaneBaseURL, operatorclient.CenterClient)
	if err != nil {
		return failure(FailureBroker, err)
	}
	browserPath = findChromiumBrowser()
	if browserPath == "" {
		return failure(FailureBrowser, errors.New("supported Chromium browser unavailable"))
	}
	localData := os.Getenv("LocalAppData")
	if !filepath.IsAbs(localData) {
		return failure(FailureProfile, errors.New("LocalAppData unavailable"))
	}
	profileRoot := filepath.Join(localData, "VGT", "GeDefense", "WebWindow")
	if err := os.MkdirAll(profileRoot, 0700); err != nil {
		return failure(FailureProfile, err)
	}
	// Each host owns its profile and process. No title search, stale lock deletion,
	// interpolated PowerShell, or termination of another browser session.
	profile, err := os.MkdirTemp(profileRoot, "center-")
	if err != nil {
		return failure(FailureProfile, err)
	}
	defer func() {
		if err := os.RemoveAll(profile); err != nil {
			log.Printf("center profile cleanup: %v", err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var workers sync.WaitGroup
	workerErr := make(chan error, 1)
	hostErr := winframe.Run(func(host winapi.Handle) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := runBrowser(ctx, host, browserPath, profile, controlPlaneURL, session.Token)
			if err != nil && ctx.Err() == nil {
				workerErr <- err
			}
			if err := winframe.Command(host, "close"); err != nil && ctx.Err() == nil {
				log.Printf("center close: %v", err)
			}
		}()
	})
	cancel()
	workers.Wait()
	select {
	case err := <-workerErr:
		return err
	default:
		return failure(FailureHost, hostErr)
	}
}

func runBrowser(ctx context.Context, host winapi.Handle, browserPath, profile, target, masterToken string) error {
	cmd := exec.CommandContext(ctx, browserPath, browserArguments(profile, target)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return failure(FailureStartup, fmt.Errorf("browser process start: %w", err))
	}
	// The browser URL contains no credential. Instead the launcher registers the
	// exact process it just started; the server accepts exactly one session
	// exchange from that process (or a descendant such as the Chromium network
	// service). A local race that reads the CommandLine gains no secret.
	if err := registerBrowserProcess(controlPlaneBaseURL, masterToken, uint32(cmd.Process.Pid)); err != nil {
		killErr := cmd.Process.Kill()
		waitErr := cmd.Wait()
		return failure(FailureBroker, errors.Join(fmt.Errorf("browser session registration: %w", err), killErr, waitErr))
	}
	processDone := make(chan error, 1)
	go func() { processDone <- cmd.Wait() }()
	browserCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(browserAttachDeadline)
	defer deadline.Stop()
	var browser winapi.Handle
	for browser == 0 {
		select {
		case <-ctx.Done():
			return <-processDone
		case err := <-processDone:
			if err == nil {
				err = errors.New("browser exited before attachment")
			}
			return failure(FailureStartup, err)
		case <-deadline.C:
			killErr := cmd.Process.Kill()
			waitErr := <-processDone
			return failure(FailureStartup, errors.Join(errors.New("browser window startup timed out"), killErr, waitErr))
		case <-ticker.C:
			// Only windows belonging to the process started above are eligible.
			if found, err := winapi.FindWindowByPID(uint32(cmd.Process.Pid)); err == nil {
				browser = found
			}
		}
	}
	if err := winframe.Attach(host, browser); err != nil {
		killErr := cmd.Process.Kill()
		waitErr := <-processDone
		return failure(FailureHost, errors.Join(err, killErr, waitErr))
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() { defer workers.Done(); runWindowCoordinator(browserCtx, host) }()
	err := <-processDone
	cancel()
	workers.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// browserArguments builds the Chromium command line. The loopback URL carries no
// bootstrap secret and the profile is a throw-away directory owned by this
// process (AN-FIND-002 / UI-FIND-004 regression target).
func browserArguments(profile, target string) []string {
	return []string{
		"--kiosk", target,
		"--user-data-dir=" + profile,
		"--no-first-run", "--no-default-browser-check",
		"--disable-background-mode", "--disable-extensions", "--disable-sync",
		"--disable-component-extensions-with-background-pages",
		"--disable-default-apps", "--disable-domain-reliability",
		"--disable-breakpad", "--no-pings", "--password-store=basic",
		"--disable-features=Translate,MediaRouter",
	}
}

// registerBrowserProcess announces the browser process id to the local control
// plane. It is authorized by the short-lived OS-identity-bound operator session,
// never by the long-lived master file credential.
func registerBrowserProcess(baseURL, operatorSessionToken string, pid uint32) error {
	body, err := json.Marshal(struct {
		PID    uint32 `json:"pid"`
		Client string `json:"client"`
	}{PID: pid, Client: centerClientName})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/session/register-browser", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+operatorSessionToken)
	request.Header.Set("Content-Type", "application/json")
	requestID, err := randomRequestID()
	if err != nil {
		return err
	}
	request.Header.Set("X-VGT-Request-ID", requestID)
	client := localhttp.NewClient(8 * time.Second)
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer cleanup.CloseInto(&err, response.Body)
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return errors.New("browser registration rejected")
	}
	return nil
}

// windowSession holds the short-lived operator session used for poll/ack. It is
// renewed from the OS-identity-bound operator broker before expiry and on a
// server-side rejection; the master token file is never read by the Center
// (UI-FIND-001 / AN-FIND-004).
type windowSession struct {
	baseURL string
	client  *http.Client
	mu      sync.Mutex
	token   string
	expires time.Time
}

func newWindowSession(baseURL string) *windowSession {
	return &windowSession{baseURL: baseURL, client: localhttp.NewClient(12 * time.Second)}
}

func (w *windowSession) authorization(ctx context.Context) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if w.token != "" && !w.expires.IsZero() && now.Add(operatorclient.RefreshBefore).Before(w.expires) {
		return "Bearer " + w.token, nil
	}
	session, err := operatorclient.Acquire(ctx, w.baseURL, operatorclient.CenterClient)
	if err != nil {
		return "", err
	}
	w.token = session.Token
	w.expires = session.Expires
	return "Bearer " + w.token, nil
}

func (w *windowSession) invalidate() {
	w.mu.Lock()
	w.token = ""
	w.expires = time.Time{}
	w.mu.Unlock()
}

func (w *windowSession) close() { w.client.CloseIdleConnections() }

func runWindowCoordinator(ctx context.Context, host winapi.Handle) {
	session := newWindowSession(controlPlaneBaseURL)
	defer session.close()
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			state, err := winapi.WindowState(host)
			if err != nil {
				return
			}
			if err := sendStateAck(ctx, session, state); err != nil && ctx.Err() == nil {
				log.Print("center state acknowledgement unavailable")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() {
		workers.Wait()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := sendStateAck(cleanup, session, "closed"); err != nil {
			log.Print("center disconnect acknowledgement unavailable")
		}
	}()
	for ctx.Err() == nil {
		err := pollWindow(ctx, session, host)
		if err != nil && ctx.Err() == nil {
			log.Print("center command connection unavailable")
			retry := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				retry.Stop()
				return
			case <-retry.C:
			}
		}
	}
}

func pollWindow(ctx context.Context, session *windowSession, host winapi.Handle) (err error) {
	for attempt := 0; attempt < 2; attempt++ {
		authorization, err := session.authorization(ctx)
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, session.baseURL+"/api/v1/window/poll", nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", authorization)
		response, err := session.client.Do(request)
		if err != nil {
			return err
		}
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			_ = response.Body.Close()
			session.invalidate()
			continue
		}
		return consumePollResponse(host, response)
	}
	return errors.New("window poll rejected")
}

func consumePollResponse(host winapi.Handle, response *http.Response) (err error) {
	defer cleanup.CloseInto(&err, response.Body)
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return errors.New("window poll rejected")
	}
	var result struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&result); err != nil {
		return err
	}
	if result.Command == "idle" {
		return nil
	}
	return winframe.Command(host, result.Command)
}

func sendStateAck(ctx context.Context, session *windowSession, state string) (err error) {
	body, err := json.Marshal(struct {
		State string `json:"state"`
	}{state})
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 2; attempt++ {
		authorization, authErr := session.authorization(ctx)
		if authErr != nil {
			return authErr
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, session.baseURL+"/api/v1/window/ack", bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", authorization)
		request.Header.Set("Content-Type", "application/json")
		requestID, err := randomRequestID()
		if err != nil {
			return err
		}
		request.Header.Set("X-VGT-Request-ID", requestID)
		response, err := session.client.Do(request)
		if err != nil {
			return err
		}
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			_ = response.Body.Close()
			session.invalidate()
			continue
		}
		return closeAckResponse(response)
	}
	return errors.New("window state rejected")
}

func closeAckResponse(response *http.Response) (err error) {
	defer cleanup.CloseInto(&err, response.Body)
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return errors.New("window state rejected")
	}
	return nil
}

// findChromiumBrowser resolves an installed Chromium browser exclusively from
// administrator-writable locations. User-writable LocalAppData candidates and
// the HKCU App Paths fallback are deliberately not consulted (CWE-426,
// UI-FIND-002). Every candidate must additionally carry a valid embedded
// Authenticode signature; an unsigned or tampered browser is never launched.
func findChromiumBrowser() string {
	candidates := browserCandidates()
	for _, candidate := range candidates {
		if isVerifiedBrowserExecutable(candidate) {
			return candidate
		}
	}
	for _, pattern := range edgeCorePatterns() {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if isVerifiedBrowserExecutable(match) {
				return match
			}
		}
	}
	for _, appName := range []string{"msedge.exe", "chrome.exe", "brave.exe"} {
		if path := trustedAppPath(appName); path != "" && isVerifiedBrowserExecutable(path) {
			return path
		}
	}
	return ""
}

// isVerifiedBrowserExecutable combines the trusted-path boundary with an
// Authenticode verification of the exact PE (UI-FIND-002 defense-in-depth).
// A verification error is fail-closed: the candidate is not launched.
func isVerifiedBrowserExecutable(path string) bool {
	if !isTrustedBrowserPath(path) || !isExecutableFile(path) {
		return false
	}
	if err := winapi.VerifyAuthenticode(path); err != nil {
		log.Printf("browser Authenticode verification rejected: %v", err)
		return false
	}
	return true
}

func browserCandidates() []string {
	roots := trustedBrowserRoots()
	candidates := make([]string, 0, 12)
	relative := [][]string{
		{"Microsoft", "Edge", "Application", "msedge.exe"},
		{"Google", "Chrome", "Application", "chrome.exe"},
		{"BraveSoftware", "Brave-Browser", "Application", "brave.exe"},
	}
	for _, root := range roots {
		for _, parts := range relative {
			candidates = append(candidates, filepath.Join(append([]string{root}, parts...)...))
		}
	}
	return candidates
}

func edgeCorePatterns() []string {
	patterns := make([]string, 0, 2)
	for _, root := range trustedBrowserRoots() {
		patterns = append(patterns, filepath.Join(root, "Microsoft", "EdgeCore", "*", "msedge.exe"))
	}
	return patterns
}

// trustedBrowserRoots returns the administrator-writable browser install roots
// of this machine. Empty or non-absolute values are dropped.
func trustedBrowserRoots() []string {
	seen := make(map[string]bool)
	roots := make([]string, 0, 2)
	for _, key := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		value := strings.TrimSpace(os.Getenv(key))
		if !filepath.IsAbs(value) {
			continue
		}
		clean := filepath.Clean(value)
		lower := strings.ToLower(clean)
		if seen[lower] {
			continue
		}
		seen[lower] = true
		roots = append(roots, clean)
	}
	return roots
}

// isTrustedBrowserPath enforces absolute containment below a trusted browser
// root, a known Chromium executable name and the absence of reparse points on
// every existing path component.
func isTrustedBrowserPath(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	clean := filepath.Clean(path)
	if !strings.EqualFold(filepath.Ext(clean), ".exe") {
		return false
	}
	switch strings.ToLower(filepath.Base(clean)) {
	case "msedge.exe", "chrome.exe", "brave.exe":
	default:
		return false
	}
	if !pathWithinTrustedRoot(clean) {
		return false
	}
	return !pathHasReparsePoint(clean)
}

func pathWithinTrustedRoot(path string) bool {
	for _, root := range trustedBrowserRoots() {
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." || strings.HasPrefix(relative, "..") || filepath.IsAbs(relative) {
			continue
		}
		return true
	}
	return false
}

// pathHasReparsePoint walks every component of an existing path and rejects
// symlinks, junctions and mount points. Missing components are not an error
// here; existence is checked separately by isExecutableFile.
func pathHasReparsePoint(path string) bool {
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume)
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(strings.Trim(remainder, `\/`), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		pointer, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			return true
		}
		attributes, err := syscall.GetFileAttributes(pointer)
		if err != nil {
			return false
		}
		if attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return true
		}
	}
	return false
}

func isExecutableFile(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// trustedAppPath reads the machine-wide App Paths registration only. The
// per-user HKCU hive is ignored because that value is user-writable.
func trustedAppPath(appName string) string {
	subKey, err := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\` + appName)
	if err != nil {
		return ""
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subKey, 0, syscall.KEY_READ, &key); err != nil {
		return ""
	}
	defer syscall.RegCloseKey(key)
	var bufferLength uint32 = 1024
	buffer := make([]uint16, bufferLength)
	if err := syscall.RegQueryValueEx(key, nil, nil, nil, (*byte)(unsafe.Pointer(&buffer[0])), &bufferLength); err != nil {
		return ""
	}
	return strings.Trim(syscall.UTF16ToString(buffer), `"`)
}

func randomRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	hexValue := hex.EncodeToString(raw)
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32], nil
}

// Diagnostic log contract for the Center launch. The file is the evidence trail
// requested by operators when "the Center does not open". It contains only the
// category, the elevated flag, the verified browser path and the bounded error
// text: never a token, never a server response body.
const (
	diagnosticLogDirectory = "logs"
	diagnosticLogFileName  = "center-launch.log"
	diagnosticLogMaxBytes  = 256 << 10
	diagnosticLogMaxLine   = 2048
)

var diagnosticLogMu sync.Mutex

type launchDiagnostic struct {
	Category string
	Elevated bool
	Browser  string
	Detail   string
}

// DiagnosticLogPath returns the absolute Center launch log path below the
// per-user local application data directory.
func DiagnosticLogPath() (string, error) {
	localData := os.Getenv("LocalAppData")
	if !filepath.IsAbs(localData) {
		return "", errors.New("LocalAppData unavailable")
	}
	return filepath.Join(filepath.Clean(localData), "VGT", "GeDefense", diagnosticLogDirectory, diagnosticLogFileName), nil
}

// RecordElevationFallback records that the elevated Center could not hand
// itself over to the unprivileged desktop shell and kept running elevated as a
// diagnostic fallback. Diagnostics are best effort and must never block the UI.
func RecordElevationFallback(err error) {
	recordLaunchDiagnostic(launchDiagnostic{
		Category: string(FailureElevation),
		Elevated: winapi.IsProcessElevated(),
		Detail:   diagnosticDetail(err),
	})
}

func diagnosticCategory(err error) string {
	if err == nil {
		return "success"
	}
	kind := KindOf(err)
	if kind == "" {
		return "unknown"
	}
	return string(kind)
}

func diagnosticDetail(err error) string {
	if err == nil {
		return "center window opened"
	}
	return err.Error()
}

func recordLaunchDiagnostic(entry launchDiagnostic) {
	if err := writeLaunchDiagnostic(entry); err != nil {
		log.Printf("center launch diagnostic unavailable: %v", err)
	}
}

// writeLaunchDiagnostic appends one bounded UTC line and rotates the log to a
// single .1 generation once the 256 KiB ceiling would be exceeded. Disk usage of
// the diagnostic trail is therefore hard-bounded to roughly twice the ceiling.
func writeLaunchDiagnostic(entry launchDiagnostic) error {
	path, err := DiagnosticLogPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	line := formatLaunchDiagnostic(entry, time.Now().UTC())
	diagnosticLogMu.Lock()
	defer diagnosticLogMu.Unlock()
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("center launch diagnostic path is a reparse point")
		}
		if info.Size()+int64(len(line)) > diagnosticLogMaxBytes {
			rotated := path + ".1"
			_ = os.Remove(rotated)
			if renameErr := os.Rename(path, rotated); renameErr != nil {
				// Bounding disk usage is mandatory; if rotation is impossible the
				// current generation is discarded instead of growing forever.
				_ = os.Remove(path)
			}
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(line)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func formatLaunchDiagnostic(entry launchDiagnostic, at time.Time) string {
	category := sanitizeDiagnosticField(entry.Category, 32)
	if category == "" {
		category = "unknown"
	}
	line := fmt.Sprintf("%s kind=%s elevated=%t browser=%q detail=%q",
		at.UTC().Format(time.RFC3339),
		category,
		entry.Elevated,
		sanitizeDiagnosticField(entry.Browser, 512),
		sanitizeDiagnosticField(entry.Detail, 1024),
	)
	if len(line) > diagnosticLogMaxLine {
		line = line[:diagnosticLogMaxLine]
	}
	return line + "\n"
}

func sanitizeDiagnosticField(value string, maxRunes int) string {
	value = strings.NewReplacer("\x00", " ", "\r", " ", "\n", " ", "\t", " ").Replace(value)
	characters := []rune(value)
	if len(characters) > maxRunes {
		characters = characters[:maxRunes]
	}
	return string(characters)
}
