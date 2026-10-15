// STATUS: PLATIN
//go:build windows

package winframe

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func TestInitialBoundsTracksMonitorWorkArea(t *testing.T) {
	for _, work := range []rect{{0, 0, 1920, 1040}, {0, 0, 3840, 2080}, {-2560, -1440, 0, 0}, {100, 200, 1100, 900}} {
		got := InitialBounds(work)
		if got.left < work.left || got.top < work.top || got.right > work.right || got.bottom > work.bottom {
			t.Fatalf("outside work area: %+v %+v", work, got)
		}
		width, height := work.right-work.left, work.bottom-work.top
		if got.right-got.left != width*92/100 || got.bottom-got.top != height*90/100 {
			t.Fatalf("fixed or undersized bounds: %+v", got)
		}
		if dx, dy := (got.left-work.left)-(work.right-got.right), (got.top-work.top)-(work.bottom-got.bottom); dx < -1 || dx > 1 || dy < -1 || dy > 1 {
			t.Fatalf("not centered: %+v", got)
		}
	}
}

// This measures the actual native gutter after the real renderer is attached,
// which the previous client-size-only test did not cover.
func assertDarkResizeEdges(host winapi.Handle) (err error) {
	var bounds rect
	result, _, callErr := procGetClientRect.Call(uintptr(host), uintptr(unsafe.Pointer(&bounds)))
	if err := winapi.CheckBOOL("GetClientRect(edge test)", result, callErr); err != nil {
		return err
	}
	getDC := user32.NewProc("GetDC")
	releaseDC := user32.NewProc("ReleaseDC")
	getPixel := gdi32.NewProc("GetPixel")
	dc, _, callErr := getDC.Call(uintptr(host))
	if dc == 0 {
		return fmt.Errorf("get edge DC: %w", callErr)
	}
	defer func() {
		r, _, e := releaseDC.Call(uintptr(host), dc)
		if e := winapi.CheckBOOL("ReleaseDC", r, e); e != nil {
			err = e
		}
	}()
	for _, p := range []point{{1, bounds.bottom / 2}, {bounds.right - 2, bounds.bottom / 2}, {bounds.right / 2, 1}, {bounds.right / 2, bounds.bottom - 2}} {
		color, _, _ := getPixel.Call(dc, uintptr(p.x), uintptr(p.y))
		if color == 0xffffffff {
			return fmt.Errorf("edge pixel unavailable: %+v", p)
		}
		if color&0xffffff != hostBackground {
			return fmt.Errorf("incorrect native edge color 0x%06x at %+v; want 0x%06x", color, p, hostBackground)
		}
	}
	return nil
}
