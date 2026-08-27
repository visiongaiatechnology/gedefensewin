// STATUS: DIAMANT VGT SUPREME
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	webview2 "github.com/jchv/go-webview2"
	"github.com/visiongaiatechnology/gedefense/windows/internal/launcher"
	"golang.org/x/sys/windows"
)

const version = "2.3.2-vgt.win17"

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()
	if *showVersion {
		notify(fmt.Sprintf("GeDefense Center %s", version), windows.MB_ICONINFORMATION)
		return
	}
	mutexName, _ := windows.UTF16PtrFromString(`Local\VGT.GeDefense.Center.v1`)
	mutex, mutexErr := windows.CreateMutex(nil, false, mutexName)
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	if mutexErr == windows.ERROR_ALREADY_EXISTS {
		return
	}
	if mutexErr != nil {
		notify("GeDefense Center konnte nicht exklusiv gestartet werden.", windows.MB_ICONERROR)
		return
	}
	target, err := launcher.BootstrapURL()
	if err != nil {
		notify("GeDefense Center konnte nicht authentifiziert werden: "+err.Error(), windows.MB_ICONERROR)
		return
	}
	dataPath, err := webViewDataPath()
	if err != nil {
		notify("GeDefense Center konnte den geschützten UI-Speicher nicht initialisieren.", windows.MB_ICONERROR)
		return
	}
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  dataPath,
		WindowOptions: webview2.WindowOptions{
			Title:  "VGT GeDefense Security Center",
			Width:  1420,
			Height: 900,
			IconId: 1,
			Center: true,
		},
	})
	if w == nil {
		notify("Microsoft WebView2 Runtime ist nicht verfügbar.", windows.MB_ICONERROR)
		return
	}
	defer w.Destroy()
	w.SetSize(1100, 700, webview2.HintMin)
	w.Navigate(target)
	w.Run()
}

func webViewDataPath() (string, error) {
	root := os.Getenv("LOCALAPPDATA")
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("LocalAppData unavailable")
	}
	path := filepath.Join(filepath.Clean(root), "VGT", "GeDefense", "WebView2")
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}
	return path, nil
}

func notify(message string, style uint32) {
	caption, _ := windows.UTF16PtrFromString("VGT GeDefense Center")
	text, _ := windows.UTF16PtrFromString(message)
	_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|style)
}
