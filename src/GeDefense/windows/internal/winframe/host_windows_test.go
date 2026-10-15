// STATUS: PLATIN
//go:build windows

package winframe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// Opt-in native integration: real Chromium, real owner HWND, no security service.
func TestNativeBrowserHost(t *testing.T) {
	if os.Getenv("GEDEFENSE_NATIVE_UI_TEST") != "1" {
		t.Skip("opt-in Windows desktop integration")
	}
	browser := os.Getenv("GEDEFENSE_NATIVE_BROWSER")
	if browser == "" {
		browser = filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe")
	}
	if _, err := os.Stat(browser); err != nil {
		t.Fatal(err)
	}
	server := nativeFixture(t)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	done := make(chan error, 1)
	err := Run(func(host winapi.Handle) {
		go func() {
			result := func() error {
				cmd := exec.CommandContext(ctx, browser, "--kiosk", server.URL, "--user-data-dir="+t.TempDir(), "--no-first-run", "--no-default-browser-check", "--disable-background-mode")
				if err := cmd.Start(); err != nil {
					return err
				}
				defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
				var child winapi.Handle
				for i := 0; i < 100; i++ {
					if found, err := winapi.FindWindowByPID(uint32(cmd.Process.Pid)); err == nil {
						child = found
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				if child == 0 {
					return errors.New("browser window missing")
				}
				if err := Attach(host, child); err != nil {
					return err
				}
				time.Sleep(time.Second)
				parent, _, _ := getParent.Call(uintptr(child))
				if parent != uintptr(host) {
					return errors.New("browser is not hosted")
				}
				initial, err := winapi.WindowState(host)
				if err != nil || initial != "maximized" {
					return fmt.Errorf("initial state=%s error=%v", initial, err)
				}
				// The client fills the host: no extra native titlebar or clipped content.
				var bounds rect
				result, _, callErr := procGetClientRect.Call(uintptr(host), uintptr(unsafe.Pointer(&bounds)))
				if err := winapi.CheckBOOL("GetClientRect(test)", result, callErr); err != nil {
					return err
				}
				actual, err := winapi.GetWindowBounds(host)
				if err != nil {
					return err
				}
				if bounds.bottom != actual.Bottom-actual.Top || bounds.right != actual.Right-actual.Left {
					return fmt.Errorf("native nonclient area remains: %+v %+v", bounds, actual)
				}
				for _, want := range []string{"normal", "maximized"} {
					if err := Command(host, "maximize"); err != nil {
						return err
					}
					time.Sleep(500 * time.Millisecond)
					got, err := winapi.WindowState(host)
					if err != nil || got != want {
						return fmt.Errorf("state=%s want=%s error=%v", got, want, err)
					}
					if want == "normal" {
						if os.Getenv("GEDEFENSE_NATIVE_PREVIEW") == "1" {
							t.Log("Native restored preview ready for visual inspection")
							select {
							case <-time.After(45 * time.Second):
							case <-ctx.Done():
								return ctx.Err()
							}
						}
						if err := assertDarkResizeEdges(host); err != nil {
							return err
						}
					}
					parent, _, _ := getParent.Call(uintptr(child))
					if parent != uintptr(host) {
						return errors.New("browser detached during resize")
					}
				}
				if err := Command(host, "minimize"); err != nil {
					return err
				}
				time.Sleep(300 * time.Millisecond)
				got, err := winapi.WindowState(host)
				if err != nil || got != "minimized" {
					return fmt.Errorf("minimize state=%s error=%v", got, err)
				}
				return nil
			}()
			done <- result
			_ = Command(host, "close")
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
