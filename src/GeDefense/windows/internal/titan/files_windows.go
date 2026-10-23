// STATUS: DIAMANT VGT SUPREME
//go:build windows

package titan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	maxHashBytes      = 64 << 20
	maxPendingChanges = 4096
	fileDebounce      = 750 * time.Millisecond
)

type fileSensor struct {
	engine             *Engine
	mu                 sync.Mutex
	pending            map[string]*time.Timer
	actions            map[string]uint32
	dropped            uint64
	lastOverflowNotice time.Time
}

func newFileSensor(engine *Engine) *fileSensor {
	return &fileSensor{engine: engine, pending: make(map[string]*time.Timer), actions: make(map[string]uint32)}
}

func (s *fileSensor) schedule(path string, action uint32) {
	if path == "" {
		return
	}
	s.mu.Lock()
	if timer, exists := s.pending[path]; exists {
		// Coalesce: an already pending path keeps its slot and only refreshes the
		// debounce/action instead of being dropped under flood pressure.
		timer.Stop()
		s.actions[path] = action
		s.pending[path] = s.newTimerLocked(path)
		s.mu.Unlock()
		return
	}
	if len(s.pending) >= maxPendingChanges {
		s.dropped++
		notify := s.lastOverflowNotice.IsZero() || time.Since(s.lastOverflowNotice) > 10*time.Second
		if notify {
			s.lastOverflowNotice = time.Now()
		}
		dropped := s.dropped
		s.mu.Unlock()
		s.engine.setWatcherOverflows(1)
		// A silent drop is a detection gap: emit a bounded security observation
		// (rate-limited to one per ten seconds) instead of only counting it.
		if notify {
			s.engine.reportWatcherLoss("WATCHER_SPOOL_DROP", path,
				fmt.Sprintf("%d Pfadereignisse verworfen; Backpressure-Grenze %d", dropped, maxPendingChanges))
		}
		return
	}
	s.actions[path] = action
	s.pending[path] = s.newTimerLocked(path)
	s.mu.Unlock()
}

func (s *fileSensor) newTimerLocked(path string) *time.Timer {
	return time.AfterFunc(fileDebounce, func() {
		s.mu.Lock()
		lastAction := s.actions[path]
		delete(s.actions, path)
		delete(s.pending, path)
		s.mu.Unlock()
		s.engine.processFileChange(path, lastAction)
	})
}

func (e *Engine) reportWatcherLoss(kind, path, detail string) {
	e.emit(Observation{
		Type: EventSensorHealth, Severity: SeverityHigh,
		Object: Object{Kind: ObjectSensor, Path: "titan://sensors/files", Name: kind},
		Source: "titan-file-watch", Health: "DEGRADED",
		Detail: detail + " (" + path + ")",
	})
}

// inspectTitanFile hashes a file through the reparse-safe handle primitive and
// rejects files that changed while being read. A path-based Lstat/open pair is
// never used for a security-relevant hash (DP-FIND-007).
func inspectTitanFile(path string) (hash string, size int64, modified time.Time, tooLarge bool, err error) {
	file, metadata, err := winapi.OpenRegularFileNoReparse(path)
	if err != nil {
		return "", 0, time.Time{}, false, err
	}
	defer func() { _ = file.Close() }()
	modified = time.Unix(0, metadata.ModifiedUnixNano).UTC()
	if metadata.Size < 0 || metadata.Size > maxHashBytes {
		return "", metadata.Size, modified, true, nil
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maxHashBytes+1))
	if err != nil {
		return "", 0, time.Time{}, false, err
	}
	if written > maxHashBytes {
		return "", metadata.Size, modified, true, nil
	}
	after, err := file.Stat()
	if err != nil {
		return "", 0, time.Time{}, false, err
	}
	if !after.Mode().IsRegular() || after.Size() != metadata.Size {
		return "", 0, time.Time{}, false, errors.New("file changed while hashing")
	}
	return hex.EncodeToString(digest.Sum(nil)), metadata.Size, modified, false, nil
}

func (e *Engine) processFileChange(path string, action uint32) {
	now := time.Now().UTC()
	fileType := classifyFile(path)
	if isKnownTelemetryNoise(path, fileType) {
		return
	}
	eventType := EventFileModified
	switch action {
	case 1, 5:
		eventType = EventFileCreated
	case 2, 4:
		eventType = EventFileDeleted
	}
	// A deletion leaves no payload to verify. For temporary build/test paths the
	// creation/modification event is the meaningful observation; suppressing the
	// trailing deletion avoids turning compiler cleanup into high-risk findings.
	if eventType == EventFileDeleted && isTemporaryPath(path) {
		return
	}
	hash, size, modified, tooLarge, err := inspectTitanFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			e.markSensor("files", SensorDegraded, "Dateizustand konnte nicht gelesen werden.")
			return
		}
		if eventType == EventFileDeleted {
			e.emit(Observation{Type: EventFileDeleted, Severity: SeverityMedium,
				Object: Object{Kind: ObjectFile, Path: path, Name: filepath.Base(path), FileType: fileType},
				Source: "titan-file-watch", Health: "HEALTHY"})
		}
		return
	}
	if tooLarge {
		e.emit(Observation{Type: eventType, Severity: SeverityHigh,
			Object: Object{Kind: ObjectFile, Path: path, Name: filepath.Base(path), Size: size,
				ModifiedUTC: modified, FileType: fileType},
			Source: "titan-file-watch", Health: "DEGRADED", Detail: "Datei überschreitet das vollständige Hash-Budget; nur Metadaten wurden beobachtet."})
		return
	}
	actor, _ := e.processContext(now)
	network := NetworkContext{CorrelationQuality: CorrelationNone}
	if classifyPath(path) == RiskIngress {
		if context, ok := e.networkContext(now); ok {
			network = context
		}
	}
	zone := readZoneIdentifier(path)
	e.emit(Observation{Type: eventType, Severity: severityForFile(path), Object: Object{
		Kind: ObjectFile, Path: path, Name: filepath.Base(path), SHA256: hash, Size: size,
		ModifiedUTC: modified, FileType: fileType, ZoneIdentifier: zone,
	}, Actor: actor, Network: network, Source: "titan-file-watch", Health: "HEALTHY"})
}

// isKnownTelemetryNoise removes high-volume OS/driver telemetry that is not an
// ingress security signal. Executables/scripts in Temp are deliberately NOT
// suppressed: those remain candidates for remote planting.
func isTemporaryPath(path string) bool {
	lower := strings.ToLower(filepath.Clean(path))
	return strings.Contains(lower, `\appdata\local\temp\`) || strings.Contains(lower, `\windows\temp\`)
}

func isKnownTelemetryNoise(path, fileType string) bool {
	lower := strings.ToLower(filepath.Clean(path))
	if strings.Contains(lower, `\windows\system32\drivers\driverdata\`) {
		return true
	}
	name := strings.ToLower(filepath.Base(lower))
	if strings.Contains(lower, `\appdata\local\temp\`) || strings.Contains(lower, `\windows\temp\`) {
		if strings.HasPrefix(name, "__psscriptpolicytest_") {
			return true
		}
		if fileType == "OTHER" || fileType == "ARCHIVE" {
			return true
		}
	}
	return false
}

func severityForFile(path string) Severity {
	class := classifyPath(path)
	if isRiskyType(classifyFile(path)) {
		switch class {
		case RiskPersistence, RiskSecurity, RiskSystem:
			return SeverityHigh
		default:
			return SeverityMedium
		}
	}
	if class == RiskPersistence || class == RiskSystem {
		return SeverityMedium
	}
	return SeverityLow
}

// readZoneIdentifier reads the bounded Zone.Identifier ADS through a size-capped
// reader. The stream size is enforced while reading, never after the whole
// stream has already been loaded into the SYSTEM process (DP-FIND-009).
func readZoneIdentifier(path string) string {
	file, err := os.Open(path + ":Zone.Identifier")
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ZoneId=") {
			value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "ZoneId="))
			if len(value) > 16 {
				value = value[:16]
			}
			return value
		}
	}
	return ""
}

func (e *Engine) defaultWatchRoots() []WatchRoot {
	roots := make([]WatchRoot, 0, 64)
	seen := make(map[string]struct{})
	add := func(path string, class RiskClass) {
		cleaned := filepath.Clean(path)
		if cleaned == "" || !filepath.IsAbs(cleaned) {
			return
		}
		key := strings.ToLower(cleaned)
		if _, exists := seen[key]; exists {
			return
		}
		if _, err := os.Stat(cleaned); err != nil {
			return
		}
		seen[key] = struct{}{}
		roots = append(roots, WatchRoot{Path: cleaned, Class: class, Active: true})
	}
	windowsRoot := os.Getenv("WINDIR")
	if windowsRoot == "" {
		windowsRoot = `C:\Windows`
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	add(filepath.Join(windowsRoot, `System32\Tasks`), RiskPersistence)
	add(filepath.Join(windowsRoot, `System32\GroupPolicy`), RiskPersistence)
	add(filepath.Join(windowsRoot, `System32\drivers`), RiskSystem)
	add(filepath.Join(windowsRoot, `System32\CodeIntegrity`), RiskSystem)
	add(filepath.Join(windowsRoot, `Temp`), RiskIngress)
	add(filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\StartUp`), RiskPersistence)
	add(`C:\Users\Public`, RiskIngress)
	usersRoot := `C:\Users`
	if systemDrive := os.Getenv("SystemDrive"); systemDrive != "" {
		usersRoot = filepath.Join(systemDrive+`\`, "Users")
	}
	userEntries, err := os.ReadDir(usersRoot)
	if err == nil {
		userCount := 0
		for _, entry := range userEntries {
			if !entry.IsDir() || userCount >= 24 {
				continue
			}
			name := strings.ToLower(entry.Name())
			if name == "public" || name == "default" || name == "default user" || name == "all users" {
				continue
			}
			home := filepath.Join(usersRoot, entry.Name())
			add(filepath.Join(home, `Desktop`), RiskIngress)
			add(filepath.Join(home, `Downloads`), RiskIngress)
			add(filepath.Join(home, `AppData\Local\Temp`), RiskIngress)
			add(filepath.Join(home, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`), RiskPersistence)
			userCount++
		}
	}
	if len(roots) > 64 {
		roots = roots[:64]
	}
	sort.Slice(roots, func(left, right int) bool {
		return strings.ToLower(roots[left].Path) < strings.ToLower(roots[right].Path)
	})
	return roots
}

func (e *Engine) runFileSensors(ctx context.Context) {
	roots := e.defaultWatchRoots()
	e.setWatchRoots(roots)
	if len(roots) == 0 {
		e.markSensor("files", SensorUnavailable, "Keine überwachbaren Dateisystemgrenzen vorhanden.")
		return
	}
	sensor := newFileSensor(e)
	for index := range roots {
		root := roots[index]
		if !root.Active {
			continue
		}
		e.sensorWG.Add(1)
		go func(root WatchRoot) {
			defer e.sensorWG.Done()
			e.watchRoot(ctx, root, sensor)
		}(root)
	}
	e.markSensor("files", SensorHealthy, "")
	e.sensorEvent("files")
}

func (e *Engine) watchRoot(ctx context.Context, root WatchRoot, sensor *fileSensor) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		watcher, err := winapi.OpenDirectoryWatcher(root.Path)
		if err != nil {
			e.markSensor("files", SensorDegraded, "Watch-Root nicht überwachbar: "+root.Path)
			e.setRootError(root.Path, err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		e.setRootActive(root.Path, true, "")
		backoff = time.Second
		for {
			changes, err := watcher.Read(ctx)
			if err != nil {
				_ = watcher.Close()
				if ctx.Err() != nil {
					return
				}
				overflow := errors.Is(err, winapi.ErrDirectoryOverflow) || isWatcherBoundaryError(err)
				if overflow {
					// A record/buffer boundary is a telemetry-loss condition, not a
					// reason to sit in exponential backoff. Surface a security event
					// and restart immediately so the blind window stays minimal.
					e.setWatcherOverflows(1)
					e.markSensor("files", SensorDegraded, "Kernel-Puffer für Dateiereignisse übergelaufen; Beobachtungsfenster neu aufgebaut.")
					e.reportWatcherLoss("WATCHER_OVERFLOW", root.Path, "Kernel-Puffer oder Record-Grenze überschritten; Ereignisse im Fenster gingen verloren.")
					e.setRootActive(root.Path, false, err.Error())
					select {
					case <-ctx.Done():
						return
					case <-time.After(100 * time.Millisecond):
					}
					break
				}
				e.markSensor("files", SensorDegraded, "Datei-Watch-Root wurde neu gestartet: "+root.Path)
				e.reportWatcherLoss("WATCHER_RESTART", root.Path, "Watcher musste nach Lesefehler neu gestartet werden: "+err.Error())
				e.setRootActive(root.Path, false, err.Error())
				break
			}
			for _, change := range changes {
				sensor.schedule(change.Path, change.Action)
			}
		}
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// isWatcherBoundaryError recognizes the bounded-record watchdog error from the
// watcher parser. That condition is a batch/overflow symptom (events were
// parsed but dropped at the API boundary), so it is handled like a kernel
// overflow instead of producing an exponential restart gap.
func isWatcherBoundaryError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "event boundary exceeded")
}

func (e *Engine) setRootActive(path string, active bool, detail string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for index := range e.watchRoots {
		if strings.EqualFold(e.watchRoots[index].Path, path) {
			e.watchRoots[index].Active = active
			e.watchRoots[index].Error = detail
			return
		}
	}
}

func (e *Engine) setRootError(path, detail string) {
	e.setRootActive(path, false, detail)
}
