// STATUS: DIAMANT VGT SUPREME
//go:build windows

package titan

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

var remoteToolNames = map[string]bool{
	"mstsc.exe": true, "rdpclip.exe": true, "wsmprovhost.exe": true, "winrdgvw.exe": true,
	"ssh.exe": true, "sshd.exe": true, "sftp-server.exe": true, "scp.exe": true,
	"winrs.exe": true, "winrm.cmd": true, "mmc.exe": true, "vncserver.exe": true,
}

var remoteLocalPorts = map[uint16]bool{
	3389: true, 5985: true, 5986: true, 445: true, 22: true, 21: true, 5900: true, 5901: true,
}

func (e *Engine) runProcessSensor(ctx context.Context) {
	e.sensorWG.Add(1)
	go func() {
		defer e.sensorWG.Done()
		previous := make(map[uint32]struct{})
		baseline := true
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				processes, err := winapi.ProcessList()
				if err != nil {
					e.markSensor("process", SensorDegraded, "Prozess-Tabelle nicht lesbar.")
					continue
				}
				current := make(map[uint32]struct{}, len(processes))
				entries := make(map[uint32]winapi.ProcessEntry, len(processes))
				for _, process := range processes {
					entries[process.PID] = process
				}
				newProcesses := make([]processObservation, 0, 8)
				for _, process := range processes {
					current[process.PID] = struct{}{}
					if baseline {
						continue
					}
					if _, exists := previous[process.PID]; exists {
						continue
					}
					observation := processObservation{ObservedUTC: time.Now().UTC(), PID: process.PID, ParentPID: process.ParentPID,
						Image: process.Image, Chain: observedProcessChain(process.PID, entries)}
					if identity, openErr := winapi.OpenProcessIdentity(process.PID, false); openErr == nil {
						observation.Path = identity.ImagePath
						observation.CreationUTC = time.Unix(0, identity.CreationUnixNano).UTC()
						if closeErr := identity.Close(); closeErr != nil {
							e.markSensor("process", SensorDegraded, "Prozess-Handle konnte nicht geschlossen werden.")
						}
					}
					newProcesses = append(newProcesses, observation)
				}
				if !baseline {
					e.observeProcesses(newProcesses)
					if len(newProcesses) > 0 {
						e.sensorEvent("process")
					}
				}
				baseline = false
				previous = current
				e.refreshRemoteTelemetry(ctx, processes)
				e.markSensor("process", SensorHealthy, "")
			}
		}
	}()
}

// observedProcessChain returns at most eight image names, leaf first. It uses
// only the process snapshot Titan actually read; a missing or reused parent PID
// terminates the chain instead of inventing ancestry.
func observedProcessChain(pid uint32, entries map[uint32]winapi.ProcessEntry) []string {
	const maxChain = 8
	chain := make([]string, 0, maxChain)
	seen := make(map[uint32]struct{}, maxChain)
	for pid != 0 && len(chain) < maxChain {
		entry, ok := entries[pid]
		if !ok || entry.Image == "" {
			break
		}
		if _, exists := seen[pid]; exists {
			break
		}
		seen[pid] = struct{}{}
		image := entry.Image
		if identity, openErr := winapi.OpenProcessIdentity(pid, false); openErr == nil {
			if identity.ImagePath != "" {
				image = identity.ImagePath
			}
			_ = identity.Close()
		}
		chain = append(chain, image)
		pid = entry.ParentPID
	}
	return chain
}

func (e *Engine) refreshRemoteTelemetry(ctx context.Context, processes []winapi.ProcessEntry) {
	if ctx.Err() != nil {
		return
	}
	connections, err := winapi.TCPConnections()
	if err != nil {
		return
	}
	images := make(map[uint32]string, len(processes))
	for _, process := range processes {
		images[process.PID] = process.Image
	}
	now := time.Now().UTC()
	for _, connection := range connections {
		if connection.State != 5 || connection.RemoteAddr.IsUnspecified() || connection.RemotePort == 0 {
			continue
		}
		if isLocalAddress(connection.RemoteAddr.String()) {
			continue
		}
		image := images[connection.PID]
		if image == "" {
			continue
		}
		if !remoteToolNames[strings.ToLower(image)] && !remoteLocalPorts[connection.LocalPort] && !remoteLocalPorts[connection.RemotePort] {
			continue
		}
		e.observeRemote(remoteObservation{ObservedUTC: now, PID: connection.PID, Image: image,
			RemoteAddress: connection.RemoteAddr.String(), RemotePort: connection.RemotePort, LocalPort: connection.LocalPort})
	}
}

func isLocalAddress(value string) bool {
	address := net.ParseIP(strings.Trim(value, "[]"))
	if address == nil {
		return true
	}
	return address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsUnspecified()
}
