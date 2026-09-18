// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	tcpEstablished         = 5
	maximumConnectionCache = 8192
)

type networkEvent struct {
	TimestampUTC time.Time
	PID          uint32
	LocalPort    uint16
	RemoteIP     string
	RemotePort   uint16
}

type networkWatcher struct{}

func (networkWatcher) Run(ctx context.Context, output chan<- networkEvent, health chan<- time.Time, faults chan<- error) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	seen := newBoundedDedupe(maximumConnectionCache)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			connections, err := winapi.TCPConnections()
			if err != nil {
				deliverFault(faults, fmt.Errorf("native TCP telemetry unavailable: %w", err))
				continue
			}
			deliverHealth(health, now.UTC())
			for _, connection := range connections {
				if connection.State != tcpEstablished || connection.PID <= 4 || !connection.RemoteAddr.IsValid() || connection.RemoteAddr.IsLoopback() || connection.RemoteAddr.IsUnspecified() || connection.RemoteAddr.IsMulticast() || connection.RemotePort == 0 {
					continue
				}
				key := fmt.Sprintf("%d|%s|%d", connection.PID, connection.RemoteAddr.String(), connection.RemotePort)
				if !seen.Admit(key, now, 5*time.Minute) {
					continue
				}
				event := networkEvent{TimestampUTC: now.UTC(), PID: connection.PID, LocalPort: connection.LocalPort, RemoteIP: connection.RemoteAddr.String(), RemotePort: connection.RemotePort}
				select {
				case output <- event:
				case <-ctx.Done():
					return
				default:
					// Backpressure is bounded; process telemetry retains priority.
				}
			}
		}
	}
}
