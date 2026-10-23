// STATUS: DIAMANT VGT SUPREME
//go:build windows

package integrity

import (
	"bufio"
	"bytes"
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

	"github.com/visiongaiatechnology/gedefense/windows/internal/cleanup"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	bucketCount          = 256
	maximumAPIChanges    = 5000
	maximumBucketRecords = 250000
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

type Engine struct {
	root       string
	statePath  string
	ledger     *evidence.Ledger
	mu         sync.RWMutex
	status     Status
	scanCancel context.CancelFunc
	scanWG     sync.WaitGroup
	closed     bool
}

func New(root string, ledger *evidence.Ledger) (*Engine, error) {
	if !filepath.IsAbs(root) || ledger == nil {
		return nil, errors.New("invalid integrity scanner configuration")
	}
	if err := os.MkdirAll(filepath.Join(root, "snapshots"), 0o700); err != nil {
		return nil, err
	}
	engine := &Engine{root: filepath.Clean(root), statePath: filepath.Join(root, "state.json"), ledger: ledger, status: Status{IntervalHours: 24, State: "DISABLED"}}
	if err := engine.load(); err != nil {
		// A rejected (unauthenticated or invalid) state is never trusted: the
		// next scan rebuilds a fresh authenticated baseline and the operator sees
		// the failure in the status projection.
		engine.status.Error = "integrity state rejected: " + err.Error()
		engine.status.State = "DEGRADED"
	}
	return engine, nil
}

func (e *Engine) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			e.mu.Lock()
			e.closed = true
			cancel := e.scanCancel
			e.mu.Unlock()
			if cancel != nil {
				cancel()
			}
			e.scanWG.Wait()
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
	// A successful operator configuration replaces a previously rejected/
	// legacy state; keeping the old error would make a healthy monitor look
	// broken forever after repair.
	e.status.Error = ""
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
	if err := e.appendEvidence("integrity.configuration", fmt.Sprintf("interval-%dh", intervalHours), map[bool]string{true: "enabled", false: "disabled"}[enabled]); err != nil {
		return e.Status(), err
	}
	if enabled && status.NextScanUTC.Before(time.Now().UTC().Add(time.Second)) {
		if startErr := e.Start(); startErr != nil {
			return e.Status(), startErr
		}
	}
	return e.Status(), nil
}

func (e *Engine) Start() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("integrity engine is stopping")
	}
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
	e.scanWG.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.scanWG.Done()
		e.scan(ctx)
	}()
	return nil
}

func (e *Engine) Changes(limit, offset int) (changes []Change, err error) {
	if limit <= 0 || limit > maximumAPIChanges || offset < 0 || offset > 10_000_000 {
		return nil, errors.New("integrity change window rejected")
	}
	status := e.Status()
	if status.Generation == "" {
		return []Change{}, nil
	}
	if !validGenerationID(status.Generation) {
		return nil, errors.New("integrity generation rejected")
	}
	directory := filepath.Join(e.root, "snapshots", status.Generation)
	manifest, manifestErr := readSnapshotManifest(directory)
	if manifestErr != nil {
		return nil, manifestErr
	}
	if err := e.authenticateSnapshotManifest(manifest); err != nil {
		return nil, err
	}
	if manifest.Generation != status.Generation {
		return nil, errors.New("integrity manifest generation mismatch")
	}
	changesDigest, hashErr := hashFileSHA256(filepath.Join(directory, "changes.jsonl"))
	if hashErr != nil {
		return nil, hashErr
	}
	if changesDigest != manifest.ChangesSHA256 {
		return nil, errors.New("integrity changes report does not match its authenticated manifest")
	}
	path := filepath.Join(directory, "changes.jsonl")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []Change{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer cleanup.CloseInto(&err, file)
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
	if err := e.writeSnapshotManifest(temporary, generation, int64(counters.hashed)); err != nil {
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
	e.pruneGenerations(maximumRetainedGenerations)
	_ = e.appendEvidence("integrity.scan", "fixed-drive-sha256", "verified")
}

type scanCounters struct{ discovered, hashed, bytes, errors uint64 }
type hashResult struct {
	record FileRecord
	err    error
}

func (e *Engine) writeSnapshot(ctx context.Context, target string) (scanCounters, error) {
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	writers := make([]*bufio.Writer, bucketCount)
	files := make([]*os.File, bucketCount)
	for index := 0; index < bucketCount; index++ {
		file, err := os.OpenFile(filepath.Join(target, fmt.Sprintf("%02x.jsonl", index)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return scanCounters{}, errors.Join(err, closeBucketFiles(files, writers))
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
			for {
				select {
				case <-workCtx.Done():
					return
				case path, ok := <-jobs:
					if !ok {
						return
					}
					record, err := hashFile(workCtx, path, buffer)
					select {
					case results <- hashResult{record: record, err: err}:
					case <-workCtx.Done():
						return
					}
				}
			}
		}()
	}

	var discovered atomic.Uint64
	var walkErrors atomic.Uint64
	walkDone := make(chan error, 1)
	go func() {
		defer close(jobs)
		walkDone <- e.walkFixedDrives(workCtx, jobs, &discovered, &walkErrors)
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	counters := scanCounters{}
	var processingErr error
	for result := range results {
		if result.err != nil {
			counters.errors++
			continue
		}
		if processingErr != nil {
			continue
		}
		payload, err := json.Marshal(result.record)
		if err != nil {
			processingErr = err
			cancel()
			continue
		}
		bucket := pathBucket(result.record.Path)
		if _, err := writers[bucket].Write(append(payload, '\n')); err != nil {
			processingErr = err
			cancel()
			continue
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
	if processingErr != nil {
		return counters, processingErr
	}
	if ctx.Err() != nil {
		return counters, ctx.Err()
	}
	if walkErr != nil && !errors.Is(walkErr, context.Canceled) {
		return counters, walkErr
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
			info, err := entry.Info()
			if err != nil {
				walkErrors.Add(1)
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				if shouldSkipDirectory(cleaned, e.root, info) {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() || isReparseInfo(info) {
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

func shouldSkipDirectory(path, scannerRoot string, info os.FileInfo) bool {
	if strings.EqualFold(path, scannerRoot) || strings.HasPrefix(strings.ToLower(path), strings.ToLower(scannerRoot)+string(os.PathSeparator)) {
		return true
	}
	if isReparseInfo(info) {
		return true
	}
	name := strings.ToLower(filepath.Base(path))
	return name == "$recycle.bin" || name == "system volume information" || name == "recovery"
}

func fixedDriveRoots() ([]string, error) {
	mask, err := winapi.LogicalDrives()
	if err != nil {
		return nil, err
	}
	roots := make([]string, 0, 4)
	for index := 0; index < 26; index++ {
		if mask&(1<<index) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+index)
		driveType, err := winapi.DriveType(root)
		if err != nil {
			return nil, err
		}
		if driveType == winapi.DriveFixed {
			roots = append(roots, root)
		}
	}
	return roots, nil
}

func hashFile(ctx context.Context, path string, buffer []byte) (record FileRecord, err error) {
	file, before, err := winapi.OpenRegularFileNoReparse(path)
	if err != nil {
		return FileRecord{}, err
	}
	defer cleanup.CloseInto(&err, file)
	hash := sha256.New()
	reader := &contextReader{ctx: ctx, reader: file}
	if _, err := io.CopyBuffer(hash, reader, buffer); err != nil {
		return FileRecord{}, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return FileRecord{}, errors.New("file state unavailable after hashing")
	}
	if info.Size() != before.Size || info.ModTime().UnixNano() != before.ModifiedUnixNano {
		return FileRecord{}, errors.New("file changed during hashing")
	}
	return FileRecord{Path: path, Size: before.Size, ModifiedUnixNano: before.ModifiedUnixNano, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
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

func (e *Engine) compare(previous, currentDirectory string) (added, modified, deleted, stored uint64, err error) {
	changesPath := filepath.Join(currentDirectory, "changes.jsonl")
	changesFile, err := os.OpenFile(changesPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	writer := bufio.NewWriterSize(changesFile, 128<<10)
	defer cleanup.CloseInto(&err, changesFile)
	if previous == "" {
		if err := writer.Flush(); err != nil {
			return 0, 0, 0, 0, err
		}
		return 0, 0, 0, 0, nil
	}
	if !validGenerationID(previous) {
		return 0, 0, 0, 0, errors.New("integrity previous generation rejected")
	}
	previousDirectory := filepath.Join(e.root, "snapshots", previous)
	previousManifest, manifestErr := readSnapshotManifest(previousDirectory)
	if manifestErr != nil {
		return 0, 0, 0, 0, manifestErr
	}
	if err := e.authenticateSnapshotManifest(previousManifest); err != nil {
		return 0, 0, 0, 0, err
	}
	if previousManifest.Generation != previous {
		return 0, 0, 0, 0, errors.New("integrity previous manifest generation mismatch")
	}
	if err := verifySnapshotBuckets(previousDirectory, previousManifest); err != nil {
		return 0, 0, 0, 0, err
	}

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

func readBucket(path string) (result map[string]FileRecord, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer cleanup.CloseInto(&err, file)
	records := make(map[string]FileRecord)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	count := 0
	for scanner.Scan() {
		count++
		if count > maximumBucketRecords {
			return nil, errors.New("integrity bucket record boundary exceeded")
		}
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
	_ = e.appendEvidence("integrity.scan", "fixed-drive-sha256", "failed")
}

func (e *Engine) persist() error {
	e.mu.RLock()
	state := persistedState{Enabled: e.status.Enabled, IntervalHours: e.status.IntervalHours, LastScanUTC: e.status.LastScanUTC, Generation: e.status.Generation, Status: e.status}
	e.mu.RUnlock()
	mac, err := e.signState(state)
	if err != nil {
		return err
	}
	state.MAC = mac
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWrite(e.statePath, append(payload, '\n'))
}

func (e *Engine) load() error {
	payload, err := os.ReadFile(e.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(payload) == 0 || len(payload) > 1<<20 {
		return errors.New("integrity state size rejected")
	}
	var state persistedState
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || (state.IntervalHours != 12 && state.IntervalHours != 24) {
		return errors.New("integrity state validation failed")
	}
	if err := e.authenticateState(state); err != nil {
		// Older GeDefense builds wrote an unsigned disabled placeholder before
		// authenticated integrity state existed. If and only if it proves to be
		// a disabled, empty state, migrate it to a signed state. Any enabled,
		// populated, generated or MAC-bearing state is still rejected fail-closed.
		if state.MAC == "" && state.Enabled == false && state.Generation == "" &&
			state.LastScanUTC.IsZero() && state.Status.Enabled == false && state.Status.State == "DISABLED" &&
			state.Status.FilesDiscovered == 0 && state.Status.FilesHashed == 0 && state.Status.BytesHashed == 0 &&
			state.Status.ReadErrors == 0 && state.Status.Added == 0 && state.Status.Modified == 0 &&
			state.Status.Deleted == 0 && state.Status.ChangesStored == 0 {
			e.status = Status{Enabled: false, IntervalHours: state.IntervalHours, State: "DISABLED"}
			if persistErr := e.persist(); persistErr != nil {
				return persistErr
			}
			_ = e.appendEvidence("integrity.migration", "legacy-disabled-placeholder", "authenticated")
			return nil
		}
		return err
	}
	if state.Generation != "" && !validGenerationID(state.Generation) {
		return errors.New("integrity state generation rejected")
	}
	state.Status.Running = false
	state.Status.StartedUTC = time.Time{}
	state.Status.Enabled = state.Enabled
	state.Status.IntervalHours = state.IntervalHours
	// A persisted error from the old, unauthenticated state schema is stale once
	// the state has authenticated successfully. Keep genuine scan errors, but do
	// not make a repaired monitor look permanently degraded.
	if strings.HasPrefix(state.Status.Error, "integrity state rejected:") {
		state.Status.Error = ""
	}
	if state.Enabled {
		state.Status.State = "SCHEDULED"
		state.Status.NextScanUTC = state.LastScanUTC.Add(time.Duration(state.IntervalHours) * time.Hour)
	} else {
		state.Status.State = "DISABLED"
	}
	e.status = state.Status
	return nil
}

func atomicWrite(path string, payload []byte) (err error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".integrity-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer cleanup.RemoveInto(&err, temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(payload)
	}
	if err == nil {
		err = temporary.Sync()
	}
	err = errors.Join(err, temporary.Close())
	if err != nil {
		return err
	}
	return winapi.MoveFileReplace(temporaryPath, path)
}
