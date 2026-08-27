// STATUS: DIAMANT VGT SUPREME
//go:build windows

package integrity

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"golang.org/x/sys/windows"
)

const (
	bucketCount       = 256
	maximumAPIChanges = 5000
)

type FileRecord struct {
	Path             string `json:"path"`
	Size             int64  `json:"size"`
	ModifiedUnixNano int64  `json:"modifiedUnixNano"`
	SHA256           string `json:"sha256"`
}

type Change struct {
	Kind       string `json:"kind"`
	Path       string `json:"path"`
	OldSHA256  string `json:"oldSha256,omitempty"`
	NewSHA256  string `json:"newSha256,omitempty"`
	Size       int64  `json:"size"`
	ModifiedAt int64  `json:"modifiedUnixNano"`
}

type Status struct {
	Enabled         bool      `json:"enabled"`
	IntervalHours   int       `json:"intervalHours"`
	State           string    `json:"state"`
	Running         bool      `json:"running"`
	StartedUTC      time.Time `json:"startedUtc,omitempty"`
	LastScanUTC     time.Time `json:"lastScanUtc,omitempty"`
	NextScanUTC     time.Time `json:"nextScanUtc,omitempty"`
	Generation      string    `json:"generation,omitempty"`
	FilesDiscovered uint64    `json:"filesDiscovered"`
	FilesHashed     uint64    `json:"filesHashed"`
	BytesHashed     uint64    `json:"bytesHashed"`
	ReadErrors      uint64    `json:"readErrors"`
	Added           uint64    `json:"added"`
	Modified        uint64    `json:"modified"`
	Deleted         uint64    `json:"deleted"`
	ChangesStored   uint64    `json:"changesStored"`
	Error           string    `json:"error,omitempty"`
}

type persistedState struct {
	Enabled       bool      `json:"enabled"`
	IntervalHours int       `json:"intervalHours"`
	LastScanUTC   time.Time `json:"lastScanUtc,omitempty"`
	Generation    string    `json:"generation,omitempty"`
	Status        Status    `json:"status"`
}

type Engine struct {
	root       string
	statePath  string
	ledger     *evidence.Ledger
	mu         sync.RWMutex
	status     Status
	scanCancel context.CancelFunc
}

func New(root string, ledger *evidence.Ledger) (*Engine, error) {
	if !filepath.IsAbs(root) || ledger == nil {
		return nil, errors.New("invalid integrity scanner configuration")
	}
	if err := os.MkdirAll(filepath.Join(root, "snapshots"), 0o700); err != nil {
		return nil, err
	}
	engine := &Engine{root: filepath.Clean(root), statePath: filepath.Join(root, "state.json"), ledger: ledger, status: Status{IntervalHours: 24, State: "DISABLED"}}
	_ = engine.load()
	return engine, nil
}

func (e *Engine) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			e.mu.Lock()
			if e.scanCancel != nil {
				e.scanCancel()
			}
			e.mu.Unlock()
			return
		case <-ticker.C:
			status := e.Status()
			if status.Enabled && !status.Running && (status.NextScanUTC.IsZero() || !time.Now().UTC().Before(status.NextScanUTC)) {
				_ = e.Start()
			}
		}
	}
}

func (e *Engine) Status() Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.status
}

func (e *Engine) Configure(enabled bool, intervalHours int) (Status, error) {
	if intervalHours != 12 && intervalHours != 24 {
		return Status{}, errors.New("integrity interval rejected")
	}
	e.mu.Lock()
	e.status.Enabled = enabled
	e.status.IntervalHours = intervalHours
	if !enabled && !e.status.Running {
		e.status.State = "DISABLED"
	}
	if enabled && !e.status.Running {
		e.status.State = "SCHEDULED"
		if e.status.LastScanUTC.IsZero() {
			e.status.NextScanUTC = time.Now().UTC()
		} else {
			e.status.NextScanUTC = e.status.LastScanUTC.Add(time.Duration(intervalHours) * time.Hour)
		}
	}
	status := e.status
	e.mu.Unlock()
	if err := e.persist(); err != nil {
		return Status{}, err
	}
	_ = e.ledger.Append("integrity.configuration", fmt.Sprintf("interval-%dh", intervalHours), map[bool]string{true: "enabled", false: "disabled"}[enabled])
	if enabled && status.NextScanUTC.Before(time.Now().UTC().Add(time.Second)) {
		_ = e.Start()
	}
	return e.Status(), nil
}

func (e *Engine) Start() error {
	e.mu.Lock()
	if e.status.Running {
		e.mu.Unlock()
		return errors.New("integrity scan already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.scanCancel = cancel
	e.status.Running = true
	e.status.State = "SCANNING"
	e.status.StartedUTC = time.Now().UTC()
	e.status.Error = ""
	e.status.FilesDiscovered = 0
	e.status.FilesHashed = 0
	e.status.BytesHashed = 0
	e.status.ReadErrors = 0
	e.mu.Unlock()
	go e.scan(ctx)
	return nil
}

func (e *Engine) Changes(limit, offset int) ([]Change, error) {
	if limit <= 0 || limit > maximumAPIChanges || offset < 0 || offset > 10_000_000 {
		return nil, errors.New("integrity change window rejected")
	}
	status := e.Status()
	if status.Generation == "" {
		return []Change{}, nil
	}
	path := filepath.Join(e.root, "snapshots", status.Generation, "changes.jsonl")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []Change{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := make([]Change, 0, limit)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	index := 0
	for scanner.Scan() {
		if index < offset {
			index++
			continue
		}
		var change Change
		if err := json.Unmarshal(scanner.Bytes(), &change); err != nil {
			return nil, errors.New("integrity report validation failed")
		}
		result = append(result, change)
		if len(result) == limit {
			break
		}
	}
	return result, scanner.Err()
}

func (e *Engine) scan(ctx context.Context) {
	previous := e.Status().Generation
	generation, err := newGenerationID()
	if err != nil {
		e.finishFailure(err)
		return
	}
	temporary := filepath.Join(e.root, "snapshots", "."+generation+".tmp")
	final := filepath.Join(e.root, "snapshots", generation)
	if err := os.Mkdir(temporary, 0o700); err != nil {
		e.finishFailure(err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	counters, err := e.writeSnapshot(ctx, temporary)
	if err != nil {
		e.finishFailure(err)
		return
	}
	added, modified, deleted, stored, err := e.compare(previous, temporary)
	if err != nil {
		e.finishFailure(err)
		return
	}
	if err := os.Rename(temporary, final); err != nil {
		e.finishFailure(err)
		return
	}
	committed = true
	now := time.Now().UTC()
	e.mu.Lock()
	e.status.Running = false
	e.status.State = map[bool]string{true: "BASELINE_CREATED", false: "VERIFIED"}[previous == ""]
	e.status.LastScanUTC = now
	e.status.NextScanUTC = now.Add(time.Duration(e.status.IntervalHours) * time.Hour)
	e.status.Generation = generation
	e.status.FilesDiscovered = counters.discovered
	e.status.FilesHashed = counters.hashed
	e.status.BytesHashed = counters.bytes
	e.status.ReadErrors = counters.errors
	e.status.Added = added
	e.status.Modified = modified
	e.status.Deleted = deleted
	e.status.ChangesStored = stored
	e.scanCancel = nil
	e.mu.Unlock()
	if err := e.persist(); err != nil {
		e.finishFailure(err)
		return
	}
	_ = e.ledger.Append("integrity.scan", "fixed-drive-sha256", "verified")
}

type scanCounters struct{ discovered, hashed, bytes, errors uint64 }
type hashResult struct {
	record FileRecord
	err    error
}

func (e *Engine) writeSnapshot(ctx context.Context, target string) (scanCounters, error) {
	writers := make([]*bufio.Writer, bucketCount)
	files := make([]*os.File, bucketCount)
	for index := 0; index < bucketCount; index++ {
		file, err := os.OpenFile(filepath.Join(target, fmt.Sprintf("%02x.jsonl", index)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			closeBucketFiles(files, writers)
			return scanCounters{}, err
		}
		files[index] = file
		writers[index] = bufio.NewWriterSize(file, 64<<10)
	}
	jobs := make(chan string, 256)
	results := make(chan hashResult, 64)
	var workers sync.WaitGroup
	workerCount := runtime.NumCPU() / 2
	if workerCount < 2 {
		workerCount = 2
	}
	if workerCount > 4 {
		workerCount = 4
	}
	for index := 0; index < workerCount; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			buffer := make([]byte, 1<<20)
			for path := range jobs {
				record, err := hashFile(ctx, path, buffer)
				select {
				case results <- hashResult{record: record, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	var discovered atomic.Uint64
	var walkErrors atomic.Uint64
	walkDone := make(chan error, 1)
	go func() {
		defer close(jobs)
		walkDone <- e.walkFixedDrives(ctx, jobs, &discovered, &walkErrors)
	}()
	go func() { workers.Wait(); close(results) }()
	counters := scanCounters{}
	for result := range results {
		if result.err != nil {
			counters.errors++
			continue
		}
		payload, err := json.Marshal(result.record)
		if err != nil {
			closeBucketFiles(files, writers)
			return counters, err
		}
		bucket := pathBucket(result.record.Path)
		if _, err := writers[bucket].Write(append(payload, '\n')); err != nil {
			closeBucketFiles(files, writers)
			return counters, err
		}
		counters.hashed++
		counters.bytes += uint64(result.record.Size)
		if counters.hashed%250 == 0 {
			e.updateProgress(discovered.Load(), counters.hashed, counters.bytes, counters.errors+walkErrors.Load())
		}
	}
	walkErr := <-walkDone
	counters.discovered = discovered.Load()
	counters.errors += walkErrors.Load()
	closeErr := closeBucketFiles(files, writers)
	if walkErr != nil {
		return counters, walkErr
	}
	if ctx.Err() != nil {
		return counters, ctx.Err()
	}
	return counters, closeErr
}

func (e *Engine) walkFixedDrives(ctx context.Context, jobs chan<- string, discovered, walkErrors *atomic.Uint64) error {
	roots, err := fixedDriveRoots()
	if err != nil {
		return err
	}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if walkErr != nil {
				walkErrors.Add(1)
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			cleaned := filepath.Clean(path)
			if entry.IsDir() {
				if shouldSkipDirectory(cleaned, e.root, entry) {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				walkErrors.Add(1)
				return nil
			}
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			discovered.Add(1)
			select {
			case jobs <- cleaned:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return ctx.Err()
}

func shouldSkipDirectory(path, scannerRoot string, entry os.DirEntry) bool {
	if strings.EqualFold(path, scannerRoot) || strings.HasPrefix(strings.ToLower(path), strings.ToLower(scannerRoot)+string(os.PathSeparator)) {
		return true
	}
	if entry.Type()&os.ModeSymlink != 0 {
		return true
	}
	name := strings.ToLower(entry.Name())
	return name == "$recycle.bin" || name == "system volume information" || name == "recovery"
}

func fixedDriveRoots() ([]string, error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, err
	}
	roots := make([]string, 0, 4)
	for index := 0; index < 26; index++ {
		if mask&(1<<index) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+index)
		pointer, err := windows.UTF16PtrFromString(root)
		if err != nil {
			return nil, err
		}
		if windows.GetDriveType(pointer) == windows.DRIVE_FIXED {
			roots = append(roots, root)
		}
	}
	return roots, nil
}

func hashFile(ctx context.Context, path string, buffer []byte) (FileRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return FileRecord{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return FileRecord{}, errors.New("file state unavailable")
	}
	hash := sha256.New()
	reader := &contextReader{ctx: ctx, reader: file}
	if _, err := io.CopyBuffer(hash, reader, buffer); err != nil {
		return FileRecord{}, err
	}
	return FileRecord{Path: path, Size: info.Size(), ModifiedUnixNano: info.ModTime().UnixNano(), SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(buffer)
	}
}

func (e *Engine) compare(previous, currentDirectory string) (uint64, uint64, uint64, uint64, error) {
	changesPath := filepath.Join(currentDirectory, "changes.jsonl")
	changesFile, err := os.OpenFile(changesPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	writer := bufio.NewWriterSize(changesFile, 128<<10)
	defer changesFile.Close()
	if previous == "" {
		if err := writer.Flush(); err != nil {
			return 0, 0, 0, 0, err
		}
		return 0, 0, 0, 0, nil
	}
	previousDirectory := filepath.Join(e.root, "snapshots", previous)
	var added, modified, deleted, stored uint64
	for index := 0; index < bucketCount; index++ {
		oldRecords, err := readBucket(filepath.Join(previousDirectory, fmt.Sprintf("%02x.jsonl", index)))
		if err != nil {
			return 0, 0, 0, 0, err
		}
		newRecords, err := readBucket(filepath.Join(currentDirectory, fmt.Sprintf("%02x.jsonl", index)))
		if err != nil {
			return 0, 0, 0, 0, err
		}
		changes := make([]Change, 0)
		for path, current := range newRecords {
			old, exists := oldRecords[path]
			if !exists {
				added++
				changes = append(changes, Change{Kind: "ADDED", Path: current.Path, NewSHA256: current.SHA256, Size: current.Size, ModifiedAt: current.ModifiedUnixNano})
			} else if old.SHA256 != current.SHA256 {
				modified++
				changes = append(changes, Change{Kind: "MODIFIED", Path: current.Path, OldSHA256: old.SHA256, NewSHA256: current.SHA256, Size: current.Size, ModifiedAt: current.ModifiedUnixNano})
			}
			delete(oldRecords, path)
		}
		for _, old := range oldRecords {
			deleted++
			changes = append(changes, Change{Kind: "DELETED", Path: old.Path, OldSHA256: old.SHA256, Size: old.Size, ModifiedAt: old.ModifiedUnixNano})
		}
		sort.Slice(changes, func(left, right int) bool {
			return strings.ToLower(changes[left].Path) < strings.ToLower(changes[right].Path)
		})
		for _, change := range changes {
			payload, err := json.Marshal(change)
			if err != nil {
				return 0, 0, 0, 0, err
			}
			if _, err := writer.Write(append(payload, '\n')); err != nil {
				return 0, 0, 0, 0, err
			}
			stored++
		}
	}
	if err := writer.Flush(); err != nil {
		return 0, 0, 0, 0, err
	}
	if err := changesFile.Sync(); err != nil {
		return 0, 0, 0, 0, err
	}
	return added, modified, deleted, stored, nil
}

func readBucket(path string) (map[string]FileRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	records := make(map[string]FileRecord)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	for scanner.Scan() {
		var record FileRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil || record.Path == "" || len(record.SHA256) != 64 {
			return nil, errors.New("integrity manifest validation failed")
		}
		records[strings.ToLower(record.Path)] = record
	}
	return records, scanner.Err()
}

func closeBucketFiles(files []*os.File, writers []*bufio.Writer) error {
	var first error
	for index := range files {
		if writers[index] != nil {
			if err := writers[index].Flush(); err != nil && first == nil {
				first = err
			}
		}
		if files[index] != nil {
			if err := files[index].Sync(); err != nil && first == nil {
				first = err
			}
			if err := files[index].Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func pathBucket(path string) byte { return sha256.Sum256([]byte(strings.ToLower(path)))[0] }

func newGenerationID() (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random), nil
}

func (e *Engine) updateProgress(discovered, hashed, bytes, readErrors uint64) {
	e.mu.Lock()
	e.status.FilesDiscovered = discovered
	e.status.FilesHashed = hashed
	e.status.BytesHashed = bytes
	e.status.ReadErrors = readErrors
	e.mu.Unlock()
}

func (e *Engine) finishFailure(err error) {
	e.mu.Lock()
	e.status.Running = false
	e.status.State = "FAILED"
	e.status.Error = err.Error()
	e.scanCancel = nil
	e.mu.Unlock()
	_ = e.ledger.Append("integrity.scan", "fixed-drive-sha256", "failed")
}

func (e *Engine) persist() error {
	e.mu.RLock()
	state := persistedState{Enabled: e.status.Enabled, IntervalHours: e.status.IntervalHours, LastScanUTC: e.status.LastScanUTC, Generation: e.status.Generation, Status: e.status}
	e.mu.RUnlock()
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWrite(e.statePath, append(payload, '\n'))
}

func (e *Engine) load() error {
	payload, err := os.ReadFile(e.statePath)
	if err != nil {
		return err
	}
	var state persistedState
	if err := json.Unmarshal(payload, &state); err != nil || (state.IntervalHours != 12 && state.IntervalHours != 24) {
		return errors.New("integrity state validation failed")
	}
	state.Status.Running = false
	state.Status.StartedUTC = time.Time{}
	state.Status.Enabled = state.Enabled
	state.Status.IntervalHours = state.IntervalHours
	if state.Enabled {
		state.Status.State = "SCHEDULED"
		state.Status.NextScanUTC = state.LastScanUTC.Add(time.Duration(state.IntervalHours) * time.Hour)
	} else {
		state.Status.State = "DISABLED"
	}
	e.status = state.Status
	return nil
}

func atomicWrite(path string, payload []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".integrity-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(payload)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
