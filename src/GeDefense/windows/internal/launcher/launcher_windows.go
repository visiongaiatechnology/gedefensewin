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
	"io"
	"log"
	"net/http"
	"net/url"
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
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winframe"
)

func Open() error {
	target, err := BootstrapURL()
	if err != nil {
		return err
	}
	return openDedicatedWindow(target)
}

func openDedicatedWindow(target string) error {
	browserPath := findChromiumBrowser()
	if browserPath == "" {
		return errors.New("supported Chromium browser unavailable")
	}
	localData := os.Getenv("LocalAppData")
	if !filepath.IsAbs(localData) {
		return errors.New("LocalAppData unavailable")
	}
	profileRoot := filepath.Join(localData, "VGT", "GeDefense", "WebWindow")
	if err := os.MkdirAll(profileRoot, 0700); err != nil {
		return err
	}
	// Each host owns its profile and process. No title search, stale lock deletion,
	// interpolated PowerShell, or termination of another browser session.
	profile, err := os.MkdirTemp(profileRoot, "center-")
	if err != nil {
		return err
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
			err := runBrowser(ctx, host, browserPath, profile, target)
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
		return hostErr
	}
}

func runBrowser(ctx context.Context, host winapi.Handle, browserPath, profile, target string) error {
	cmd := exec.CommandContext(ctx, browserPath,
		"--kiosk", target, "--user-data-dir="+profile,
		"--no-first-run", "--no-default-browser-check", "--disable-background-mode",
		"--disable-extensions", "--disable-sync", "--disable-features=Translate",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return err
	}
	processDone := make(chan error, 1)
	go func() { processDone <- cmd.Wait() }()
	browserCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(15 * time.Second)
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
			return err
		case <-deadline.C:
			killErr := cmd.Process.Kill()
			waitErr := <-processDone
			return errors.Join(errors.New("browser window startup timed out"), killErr, waitErr)
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
		return errors.Join(err, killErr, waitErr)
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

func runWindowCoordinator(ctx context.Context, host winapi.Handle) {
	programData := os.Getenv("ProgramData")
	if !filepath.IsAbs(programData) {
		log.Print("center credentials directory unavailable")
		return
	}
	rawToken, err := os.ReadFile(filepath.Join(programData, "VGT", "GeDefense", "dashboard.token"))
	if err != nil {
		log.Print("center credentials unavailable")
		return
	}
	token := strings.TrimSpace(string(rawToken))
	if len(token) != 43 {
		log.Print("center credential invalid")
		return
	}
	client := localhttp.NewClient(12 * time.Second)
	defer client.CloseIdleConnections()
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
			if err := sendStateAck(ctx, client, token, state); err != nil && ctx.Err() == nil {
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
		if err := sendStateAck(cleanup, client, token, "closed"); err != nil {
			log.Print("center disconnect acknowledgement unavailable")
		}
	}()
	for ctx.Err() == nil {
		err := pollWindow(ctx, client, token, host)
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

func pollWindow(ctx context.Context, client *http.Client, token string, host winapi.Handle) (err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:17831/api/v1/window/poll", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer cleanup.CloseInto(&err, response.Body)
	if response.StatusCode != http.StatusOK {
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

func sendStateAck(ctx context.Context, client *http.Client, token, state string) (err error) {
	body, err := json.Marshal(struct {
		State string `json:"state"`
	}{state})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:17831/api/v1/window/ack", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	id, err := randomRequestID()
	if err != nil {
		return err
	}
	req.Header.Set("X-VGT-Request-ID", id)
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer cleanup.CloseInto(&err, response.Body)
	if response.StatusCode != http.StatusOK {
		return errors.New("window state rejected")
	}
	return nil
}

func findChromiumBrowser() string {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("LocalAppData"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("LocalAppData"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
		filepath.Join(os.Getenv("LocalAppData"), "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
	}
	for _, c := range candidates {
		if isExecutableFile(c) {
			return c
		}
	}
	for _, pattern := range []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "EdgeCore", "*", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "EdgeCore", "*", "msedge.exe"),
	} {
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, m := range matches {
				if isExecutableFile(m) {
					return m
				}
			}
		}
	}
	for _, appName := range []string{"msedge.exe", "chrome.exe", "brave.exe"} {
		if p := queryAppPath(appName); p != "" && isExecutableFile(p) {
			return p
		}
	}
	return ""
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

func queryAppPath(appName string) string {
	subKey, err := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\` + appName)
	if err != nil {
		return ""
	}
	for _, root := range []syscall.Handle{syscall.HKEY_LOCAL_MACHINE, syscall.HKEY_CURRENT_USER} {
		var hKey syscall.Handle
		if err := syscall.RegOpenKeyEx(root, subKey, 0, syscall.KEY_READ, &hKey); err != nil {
			continue
		}
		var bufLen uint32 = 1024
		buf := make([]uint16, bufLen)
		queryErr := syscall.RegQueryValueEx(hKey, nil, nil, nil, (*byte)(unsafe.Pointer(&buf[0])), &bufLen)
		_ = syscall.RegCloseKey(hKey)
		if queryErr == nil {
			val := strings.Trim(syscall.UTF16ToString(buf), `"`)
			if val != "" {
				return val
			}
		}
	}
	return ""
}

func BootstrapURL() (target string, err error) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return "", errors.New("ProgramData is unavailable")
	}
	rawToken, err := os.ReadFile(filepath.Join(filepath.Clean(programData), "VGT", "GeDefense", "dashboard.token"))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(rawToken))
	if len(token) != 43 {
		return "", errors.New("dashboard credential is invalid")
	}
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/session/bootstrap", bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	requestID, err := randomRequestID()
	if err != nil {
		return "", err
	}
	request.Header.Set("X-VGT-Request-ID", requestID)
	client := localhttp.NewClient(8 * time.Second)
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer cleanup.CloseInto(&err, response.Body)
	limited, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(limited) > 4096 || response.StatusCode != http.StatusCreated {
		return "", errors.New("dashboard bootstrap failed")
	}
	var payload struct {
		Code string `json:"code"`
	}
	decoder := json.NewDecoder(bytes.NewReader(limited))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || len(payload.Code) != 43 {
		return "", errors.New("dashboard bootstrap response is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("dashboard bootstrap response contains trailing data")
	}
	return "http://127.0.0.1:17831/#bootstrap=" + url.QueryEscape(payload.Code), nil
}

func randomRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	hexValue := hex.EncodeToString(raw)
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32], nil
}
