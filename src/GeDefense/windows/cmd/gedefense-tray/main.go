// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
)

const version = "2.3.2-vgt.win17"

//go:embed gedefense.ico
var trayIcon []byte

func main() {
	showVersion := flag.Bool("version", false, "show version")
	_ = flag.Bool("tray", false, "start in notification-area mode")
	openAtStart := flag.Bool("open", false, "open the security center after tray initialization")
	flag.Parse()
	if *showVersion {
		return
	}
	primary, event, mutex, err := claimInstance()
	if err != nil {
		return
	}
	if !primary {
		_ = windows.SetEvent(event)
		_ = windows.CloseHandle(event)
		if mutex != 0 {
			_ = windows.CloseHandle(mutex)
		}
		return
	}
	defer windows.CloseHandle(event)
	defer windows.CloseHandle(mutex)
	systray.Run(func() {
		systray.SetIcon(trayIcon)
		systray.SetTooltip("VGT GeDefense · Schutzstatus wird geprüft")
		openItem := systray.AddMenuItem("GeDefense öffnen", "VGT GeDefense Security Center öffnen")
		statusItem := systray.AddMenuItem("Schutzstatus: Prüfung läuft", "Lokaler Defender- und Systemstatus")
		statusItem.Disable()
		versionItem := systray.AddMenuItem("Version "+version, "Installierter GeDefense Desktop Host")
		versionItem.Disable()
		systray.AddSeparator()
		quitItem := systray.AddMenuItem("Tray beenden", "Der GeDefense-Dienst und Microsoft Defender bleiben aktiv")
		openCenter := func() { _ = startCenter() }
		systray.SetOnTapped(openCenter)
		go func() {
			for range openItem.ClickedCh {
				openCenter()
			}
		}()
		go func() {
			for range quitItem.ClickedCh {
				systray.Quit()
			}
		}()
		go watchOpenEvent(event, openCenter)
		go monitorStatus(statusItem)
		if *openAtStart {
			go openCenter()
		}
	}, func() {})
}

func claimInstance() (bool, windows.Handle, windows.Handle, error) {
	eventName, _ := windows.UTF16PtrFromString(`Local\VGT.GeDefense.Tray.Open.v1`)
	event, err := windows.CreateEvent(nil, 0, 0, eventName)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return false, 0, 0, err
	}
	mutexName, _ := windows.UTF16PtrFromString(`Local\VGT.GeDefense.Tray.Instance.v1`)
	mutex, mutexErr := windows.CreateMutex(nil, false, mutexName)
	if mutexErr != nil && !errors.Is(mutexErr, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(event)
		return false, 0, 0, mutexErr
	}
	return !errors.Is(mutexErr, windows.ERROR_ALREADY_EXISTS), event, mutex, nil
}

func watchOpenEvent(event windows.Handle, openCenter func()) {
	for {
		result, err := windows.WaitForSingleObject(event, windows.INFINITE)
		if err != nil || result != windows.WAIT_OBJECT_0 {
			return
		}
		openCenter()
	}
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
	return exec.Command(center).Start()
}

func monitorStatus(item *systray.MenuItem) {
	refresh := func() {
		healthy, detail := protectionHealthy()
		if healthy {
			item.SetTitle("Schutzstatus: Aktiv")
			systray.SetTooltip("VGT GeDefense · Schutz aktiv")
		} else {
			item.SetTitle("Schutzstatus: " + detail)
			systray.SetTooltip("VGT GeDefense · " + detail)
		}
	}
	refresh()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		refresh()
	}
}

func protectionHealthy() (bool, string) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return false, "Status nicht verfügbar"
	}
	rawToken, err := os.ReadFile(filepath.Join(programData, "VGT", "GeDefense", "dashboard.token"))
	if err != nil {
		return false, "Operatorzugriff erforderlich"
	}
	token := strings.TrimSpace(string(rawToken))
	if len(token) != 43 {
		return false, "Status nicht verfügbar"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:17831/api/v1/status", nil)
	if err != nil {
		return false, "Status nicht verfügbar"
	}
	request.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 12 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return false, "Dienst nicht erreichbar"
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, "Prüfung erforderlich"
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
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, (1<<20)+1))
	if err := decoder.Decode(&result); err != nil {
		return false, "Status nicht verfügbar"
	}
	p := result.Protection
	if p.Defender && p.DefenderService && p.RealTimeProtection && p.CloudProtection && p.NetworkProtection && p.Firewall && p.WindowsUpdate {
		return true, "Aktiv"
	}
	return false, "Prüfung erforderlich"
}
