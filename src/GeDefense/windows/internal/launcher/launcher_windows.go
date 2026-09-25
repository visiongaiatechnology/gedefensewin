// STATUS: DIAMANT VGT SUPREME
//go:build windows

package launcher

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/localhttp"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func Open() error {
	target, err := BootstrapURL()
	if err != nil {
		return err
	}
	if err := openDedicatedWindow(target); err == nil {
		return nil
	}
	return winapi.ShellOpenURL(target)
}

func openDedicatedWindow(target string) error {
	browserPath := findChromiumBrowser()
	if browserPath == "" {
		return errors.New("no supported Chromium browser found for dedicated window")
	}
	localAppData := os.Getenv("LocalAppData")
	if localAppData == "" || !filepath.IsAbs(localAppData) {
		return errors.New("LocalAppData unavailable")
	}
	userDataDir := filepath.Join(filepath.Clean(localAppData), "VGT", "GeDefense", "WebWindow")
	if err := os.MkdirAll(userDataDir, 0700); err != nil {
		return err
	}
	args := []string{
		"--app=" + target,
		"--user-data-dir=" + userDataDir,
		"--window-size=1280,820",
		"--disable-features=Translate",
		"--no-first-run",
		"--no-default-browser-check",
	}
	cmd := exec.Command(browserPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if cmd.Process != nil {
		_ = cmd.Process.Release()
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

func BootstrapURL() (string, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return "", errors.New("ProgramData is unavailable")
	}
	rawToken, err := os.ReadFile(filepath.Join(programData, "VGT", "GeDefense", "dashboard.token"))
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
	defer response.Body.Close()
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
