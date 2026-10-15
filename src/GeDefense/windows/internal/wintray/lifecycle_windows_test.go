// STATUS: PLATIN
//go:build windows

package wintray

import (
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func TestOpenEventWatcherStopsBeforeHandleRelease(t *testing.T) {
	event, _, err := winapi.CreateEvent("", false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := winapi.CloseHandle(event); err != nil {
			t.Errorf("close fixture event: %v", err)
		}
	}()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); watchOpenEvent(uintptr(event), 0, stop) }()
	// Cancellation must interrupt an otherwise indefinitely idle event watcher.
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("open-event watcher outlived cancellation")
	}
}
