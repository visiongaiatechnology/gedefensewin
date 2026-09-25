// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"errors"
	"testing"
)

func TestWindowOperations_InvalidHandle(t *testing.T) {
	if err := MinimizeWindow(0); err == nil {
		t.Fatal("expected error on MinimizeWindow(0)")
	}
	if _, err := MaximizeOrRestoreWindow(0); err == nil {
		t.Fatal("expected error on MaximizeOrRestoreWindow(0)")
	}
	if err := CloseWindow(0); err == nil {
		t.Fatal("expected error on CloseWindow(0)")
	}
	if _, err := WindowState(0); err == nil {
		t.Fatal("expected error on WindowState(0)")
	}
}

func TestFindGeDefenseWindow_NoPanic(t *testing.T) {
	// Must not panic, returns either a valid handle or ErrWindowNotFound
	hwnd, err := FindGeDefenseWindow()
	if err != nil && !errors.Is(err, ErrWindowNotFound) {
		t.Fatalf("unexpected error: %v", err)
	}
	if err == nil && hwnd == 0 {
		t.Fatal("expected non-zero handle when error is nil")
	}
}
