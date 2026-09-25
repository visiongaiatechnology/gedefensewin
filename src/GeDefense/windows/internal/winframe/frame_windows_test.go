// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winframe

import (
	"testing"
)

func TestCalculateHitTest_ResizingBorders(t *testing.T) {
	const (
		w            int32 = 1000
		h            int32 = 700
		border       int32 = 6
		titlebarH    int32 = 38
		buttonsWidth int32 = 138
	)

	// Corners
	if hit := CalculateHitTest(2, 2, w, h, border, titlebarH, buttonsWidth); hit != htTopLeft {
		t.Fatalf("expected htTopLeft, got %d", hit)
	}
	if hit := CalculateHitTest(w-2, 2, w, h, border, titlebarH, buttonsWidth); hit != htTopRight {
		t.Fatalf("expected htTopRight, got %d", hit)
	}
	if hit := CalculateHitTest(2, h-2, w, h, border, titlebarH, buttonsWidth); hit != htBottomLeft {
		t.Fatalf("expected htBottomLeft, got %d", hit)
	}
	if hit := CalculateHitTest(w-2, h-2, w, h, border, titlebarH, buttonsWidth); hit != htBottomRight {
		t.Fatalf("expected htBottomRight, got %d", hit)
	}

	// Edges
	if hit := CalculateHitTest(w/2, 2, w, h, border, titlebarH, buttonsWidth); hit != htTop {
		t.Fatalf("expected htTop, got %d", hit)
	}
	if hit := CalculateHitTest(w/2, h-2, w, h, border, titlebarH, buttonsWidth); hit != htBottom {
		t.Fatalf("expected htBottom, got %d", hit)
	}
	if hit := CalculateHitTest(2, h/2, w, h, border, titlebarH, buttonsWidth); hit != htLeft {
		t.Fatalf("expected htLeft, got %d", hit)
	}
	if hit := CalculateHitTest(w-2, h/2, w, h, border, titlebarH, buttonsWidth); hit != htRight {
		t.Fatalf("expected htRight, got %d", hit)
	}
}

func TestCalculateHitTest_TitlebarAndButtons(t *testing.T) {
	const (
		w            int32 = 1000
		h            int32 = 700
		border       int32 = 6
		titlebarH    int32 = 38
		buttonsWidth int32 = 138
	)

	// In titlebar drag zone (e.g. x=200, y=20) -> htCaption
	if hit := CalculateHitTest(200, 20, w, h, border, titlebarH, buttonsWidth); hit != htCaption {
		t.Fatalf("expected htCaption for titlebar drag, got %d", hit)
	}

	// In titlebar buttons zone (e.g. x=w-50, y=20) -> htClient
	if hit := CalculateHitTest(w-50, 20, w, h, border, titlebarH, buttonsWidth); hit != htClient {
		t.Fatalf("expected htClient for buttons area, got %d", hit)
	}

	// In main client area (e.g. x=500, y=300) -> htClient
	if hit := CalculateHitTest(500, 300, w, h, border, titlebarH, buttonsWidth); hit != htClient {
		t.Fatalf("expected htClient for main client area, got %d", hit)
	}
}

func TestConfigureDWM_InvalidHandle(t *testing.T) {
	if err := ConfigureDWM(0); err == nil {
		t.Fatal("expected error on ConfigureDWM(0)")
	}
}
