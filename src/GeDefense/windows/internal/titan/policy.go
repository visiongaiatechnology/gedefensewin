// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxPolicyBytes = 64 << 10
	maxPermits     = 128
	maxPermitTTL   = 30 * 24 * time.Hour
)

var validPermitActions = map[string]bool{
	string(EventFileCreated): true, string(EventFileModified): true, string(EventFileDeleted): true,
	string(EventPersistenceAdded): true, string(EventPersistenceChanged): true,
	string(EventSecurityChanged): true, string(EventSecurityDowngrade): true,
	"ALLOW_CHANGE": true,
}

// PolicyStore owns the persisted owner policy. It is intentionally independent
// from the administrator token store: operator API auth is required to call it,
// but admin rights alone never become a Titan authorization.
type PolicyStore struct {
	mu             sync.Mutex
	path           string
	current        Policy
	clockHighWater time.Time
	clockRollback  bool
}

// permitClockTolerance is how far the wall clock may move backwards before
// permits are treated as untrusted. A rolled-back clock must never extend an
// expired temporary authorization (DP-FIND-014).
const permitClockTolerance = 5 * time.Minute

func OpenPolicyStore(path string) (*PolicyStore, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("titan policy path must be absolute")
	}
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	store := &PolicyStore{path: filepath.Clean(path)}
	raw, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		policy := DefaultPolicy("Initiale Titan-Richtlinie: ausschließlich beobachten, keine automatische Quarantäne")
		if err := store.persist(policy); err != nil {
			return nil, err
		}
		store.current = policy
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxPolicyBytes {
		return nil, errors.New("titan policy size rejected")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("titan policy validation: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("titan policy trailing data rejected")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	store.current = policy
	store.clockHighWater = policy.ClockHighWaterUTC
	store.observeClockLocked(time.Now().UTC())
	return store, nil
}

func DefaultPolicy(reason string) Policy {
	return Policy{
		SchemaVersion:     PolicySchemaVersion,
		Mode:              ModeObserve,
		AutoQuarantine:    false,
		Permits:           []Permit{},
		DevelopmentRoots:  []string{},
		UpdatedUTC:        time.Now().UTC(),
		Reason:            reason,
		ClockHighWaterUTC: time.Now().UTC(),
	}
}

func (p Policy) Validate() error {
	if p.SchemaVersion != PolicySchemaVersion {
		return errors.New("titan policy schema is unsupported")
	}
	switch p.Mode {
	case ModeObserve, ModeContain, ModeStrict:
	default:
		return errors.New("titan policy mode is invalid")
	}
	if p.Mode == ModeObserve && p.AutoQuarantine {
		return errors.New("automatic quarantine requires CONTAIN or STRICT")
	}
	reason := strings.TrimSpace(p.Reason)
	if len(reason) < 8 || len(reason) > 512 {
		return errors.New("titan policy reason boundary rejected")
	}
	if len(p.Permits) > maxPermits {
		return errors.New("titan permit count boundary rejected")
	}
	if !p.ClockHighWaterUTC.IsZero() && p.ClockHighWaterUTC.After(time.Now().UTC().Add(24*time.Hour)) {
		return errors.New("titan permit clock anchor rejected")
	}
	seenRoots := make(map[string]struct{}, len(p.DevelopmentRoots))
	if len(p.DevelopmentRoots) > 32 {
		return errors.New("titan development root count boundary rejected")
	}
	for _, root := range p.DevelopmentRoots {
		normalized := filepath.Clean(strings.TrimSpace(root))
		if !filepath.IsAbs(normalized) || len(normalized) > 260 {
			return errors.New("titan development root path rejected")
		}
		lower := strings.ToLower(normalized)
		if lower == `c:\` || lower == `c:\windows` || strings.HasPrefix(lower, `c:\windows\`) ||
			lower == `c:\program files` || strings.HasPrefix(lower, `c:\program files\`) ||
			lower == `c:\programdata` || strings.HasPrefix(lower, `c:\programdata\`) {
			return errors.New("titan development root must not cover a protected system tree")
		}
		if _, exists := seenRoots[lower]; exists {
			return errors.New("titan development root duplicated")
		}
		seenRoots[lower] = struct{}{}
	}
	seenOwnerImages := make(map[string]struct{}, len(p.OwnerProcessImages))
	if len(p.OwnerProcessImages) > 32 {
		return errors.New("titan owner process image count boundary rejected")
	}
	for _, image := range p.OwnerProcessImages {
		normalized := filepath.Clean(strings.TrimSpace(image))
		if !filepath.IsAbs(normalized) || len(normalized) > 260 || !strings.EqualFold(filepath.Ext(normalized), ".exe") {
			return errors.New("titan owner process image path rejected")
		}
		lower := strings.ToLower(normalized)
		if _, exists := seenOwnerImages[lower]; exists {
			return errors.New("titan owner process image duplicated")
		}
		seenOwnerImages[lower] = struct{}{}
	}
	seen := make(map[string]struct{}, len(p.Permits))
	for _, permit := range p.Permits {
		if permit.ID == "" || len(permit.ID) > 64 {
			return errors.New("titan permit id rejected")
		}
		if _, exists := seen[permit.ID]; exists {
			return errors.New("titan permit id duplicated")
		}
		seen[permit.ID] = struct{}{}
		if !filepath.IsAbs(permit.Path) || len(permit.Path) > 260 {
			return errors.New("titan permit path rejected")
		}
		if permit.SHA256 != "" && !validSHA256(permit.SHA256) {
			return errors.New("titan permit hash rejected")
		}
		if !validPermitActions[permit.Action] {
			return errors.New("titan permit action rejected")
		}
		if permit.CreatedUTC.IsZero() || permit.ExpiresUTC.IsZero() || permit.ExpiresUTC.Before(permit.CreatedUTC) ||
			permit.ExpiresUTC.After(permit.CreatedUTC.Add(maxPermitTTL)) {
			return errors.New("titan permit expiry rejected")
		}
		if len(strings.TrimSpace(permit.Reason)) < 8 || len(permit.Reason) > 512 {
			return errors.New("titan permit reason rejected")
		}
	}
	return nil
}

func (s *PolicyStore) Current() Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clonePolicy(s.current)
}

func (s *PolicyStore) RemovePermit(id, reason string) (Policy, error) {
	id = strings.TrimSpace(id)
	reason = strings.TrimSpace(reason)
	if id == "" || len(id) > 64 {
		return Policy{}, errors.New("titan permit id rejected")
	}
	if len(reason) < 8 || len(reason) > 512 {
		return Policy{}, errors.New("titan permit reason boundary rejected")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clonePolicy(s.current)
	index := -1
	for position := range next.Permits {
		if next.Permits[position].ID == id {
			index = position
			break
		}
	}
	if index < 0 {
		return Policy{}, errors.New("titan permit not found")
	}
	next.Permits = append(next.Permits[:index], next.Permits[index+1:]...)
	next.UpdatedUTC = time.Now().UTC()
	next.Reason = reason
	if err := next.Validate(); err != nil {
		return Policy{}, err
	}
	if err := s.persist(next); err != nil {
		return Policy{}, err
	}
	s.current = next
	return clonePolicy(next), nil
}

func (s *PolicyStore) IsDevelopmentPath(path string) bool {
	if path == "" {
		return false
	}
	cleaned := strings.ToLower(filepath.Clean(path))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, root := range s.current.DevelopmentRoots {
		normalized := strings.ToLower(filepath.Clean(root))
		if normalized == "" {
			continue
		}
		if cleaned == normalized || strings.HasPrefix(cleaned, normalized+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func (s *PolicyStore) AddDevelopmentRoot(path, reason string) (Policy, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || len(path) > 260 {
		return Policy{}, errors.New("titan development root path rejected")
	}
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 512 {
		return Policy{}, errors.New("titan development root reason boundary rejected")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clonePolicy(s.current)
	for _, existing := range next.DevelopmentRoots {
		if strings.EqualFold(filepath.Clean(existing), path) {
			return clonePolicy(next), nil
		}
	}
	next.DevelopmentRoots = append(next.DevelopmentRoots, path)
	next.UpdatedUTC = time.Now().UTC()
	next.Reason = reason
	if err := next.Validate(); err != nil {
		return Policy{}, err
	}
	if err := s.persist(next); err != nil {
		return Policy{}, err
	}
	s.current = next
	return clonePolicy(next), nil
}

func (s *PolicyStore) SetOwnerProcessImages(images []string, reason string) (Policy, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 512 {
		return Policy{}, errors.New("titan owner process reason boundary rejected")
	}
	normalized := make([]string, 0, len(images))
	seen := make(map[string]struct{}, len(images))
	for _, image := range images {
		path := filepath.Clean(strings.TrimSpace(image))
		if !filepath.IsAbs(path) || len(path) > 260 || !strings.EqualFold(filepath.Ext(path), ".exe") {
			return Policy{}, errors.New("titan owner process image path rejected")
		}
		lower := strings.ToLower(path)
		if _, exists := seen[lower]; exists {
			continue
		}
		seen[lower] = struct{}{}
		normalized = append(normalized, path)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clonePolicy(s.current)
	next.OwnerProcessImages = normalized
	next.UpdatedUTC = time.Now().UTC()
	next.Reason = reason
	if err := next.Validate(); err != nil {
		return Policy{}, err
	}
	if err := s.persist(next); err != nil {
		return Policy{}, err
	}
	s.current = next
	return clonePolicy(next), nil
}

func (s *PolicyStore) RemoveDevelopmentRoot(path, reason string) (Policy, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	reason = strings.TrimSpace(reason)
	if !filepath.IsAbs(path) || len(path) > 260 {
		return Policy{}, errors.New("titan development root path rejected")
	}
	if len(reason) < 8 || len(reason) > 512 {
		return Policy{}, errors.New("titan development root reason boundary rejected")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clonePolicy(s.current)
	filtered := make([]string, 0, len(next.DevelopmentRoots))
	removed := false
	for _, existing := range next.DevelopmentRoots {
		if strings.EqualFold(filepath.Clean(existing), path) {
			removed = true
			continue
		}
		filtered = append(filtered, existing)
	}
	if !removed {
		return Policy{}, errors.New("titan development root not found")
	}
	next.DevelopmentRoots = filtered
	next.UpdatedUTC = time.Now().UTC()
	next.Reason = reason
	if err := next.Validate(); err != nil {
		return Policy{}, err
	}
	if err := s.persist(next); err != nil {
		return Policy{}, err
	}
	s.current = next
	return clonePolicy(next), nil
}

func (s *PolicyStore) SetMode(mode string, autoQuarantine bool, reason string) (Policy, error) {
	mode = strings.ToUpper(strings.TrimSpace(mode))
	if mode != ModeObserve && mode != ModeContain && mode != ModeStrict {
		return Policy{}, errors.New("titan policy mode rejected")
	}
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 512 {
		return Policy{}, errors.New("titan policy reason boundary rejected")
	}
	if mode == ModeObserve {
		autoQuarantine = false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clonePolicy(s.current)
	next.Mode = mode
	next.AutoQuarantine = autoQuarantine
	next.UpdatedUTC = time.Now().UTC()
	next.Reason = reason
	if err := next.Validate(); err != nil {
		return Policy{}, err
	}
	if err := s.persist(next); err != nil {
		return Policy{}, err
	}
	s.current = next
	return clonePolicy(next), nil
}

// AddPermit creates a scoped, expiring authorization. Permits are not a
// replacement for owner policy; they are an explicit exception for one change.
func (s *PolicyStore) AddPermit(path, sha256, action string, ttl time.Duration, singleUse bool, reason string) (Permit, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || len(path) > 260 || len(path) == 0 {
		return Permit{}, errors.New("titan permit path rejected")
	}
	sha256 = strings.ToUpper(strings.TrimSpace(sha256))
	if sha256 != "" && !validSHA256(sha256) {
		return Permit{}, errors.New("titan permit hash rejected")
	}
	action = strings.TrimSpace(action)
	if action == "" {
		action = "ALLOW_CHANGE"
	}
	if !validPermitActions[action] {
		return Permit{}, errors.New("titan permit action rejected")
	}
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 512 {
		return Permit{}, errors.New("titan permit reason boundary rejected")
	}
	if ttl <= 0 || ttl > maxPermitTTL {
		return Permit{}, errors.New("titan permit ttl rejected")
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return Permit{}, err
	}
	now := time.Now().UTC()
	permit := Permit{ID: "permit-" + hex.EncodeToString(random), Path: path, SHA256: sha256, Action: action,
		CreatedUTC: now, ExpiresUTC: now.Add(ttl), SingleUse: singleUse, Reason: reason}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observeClockLocked(now)
	next := clonePolicy(s.current)
	if len(next.Permits) >= maxPermits {
		return Permit{}, errors.New("titan permit count boundary reached")
	}
	next.Permits = append(next.Permits, permit)
	next.UpdatedUTC = now
	next.Reason = reason
	if err := next.Validate(); err != nil {
		return Permit{}, err
	}
	if err := s.persist(next); err != nil {
		return Permit{}, err
	}
	s.current = next
	return permit, nil
}

// ConsumePermit atomically matches an event to a live permit and, for
// single-use permits, burns it before the event is recorded.
func (s *PolicyStore) ConsumePermit(path, sha256, eventType string, now time.Time) *Permit {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.observeClockLocked(now) {
		// Wall clock moved backwards past the trusted high-water mark. Treat all
		// permits as expired until the clock catches up: fail closed.
		return nil
	}
	path = filepath.Clean(path)
	sha256 = strings.ToUpper(sha256)
	changed := false
	for index := range s.current.Permits {
		permit := &s.current.Permits[index]
		if permit.Used || !now.Before(permit.ExpiresUTC) {
			continue
		}
		if !strings.EqualFold(filepath.Clean(permit.Path), path) {
			continue
		}
		if permit.SHA256 != "" && !strings.EqualFold(permit.SHA256, sha256) {
			continue
		}
		if permit.Action != "ALLOW_CHANGE" && permit.Action != eventType {
			continue
		}
		matched := *permit
		if permit.SingleUse {
			permit.Used = true
			s.current.UpdatedUTC = now
			changed = true
		}
		if changed {
			_ = s.persist(s.current)
		}
		return &matched
	}
	return nil
}

// observeClockLocked updates the wall-clock high-water anchor and reports
// whether the supplied timestamp is implausibly far behind it.
func (s *PolicyStore) observeClockLocked(now time.Time) bool {
	if s.clockHighWater.IsZero() {
		s.clockHighWater = now
		return false
	}
	if now.Add(permitClockTolerance).Before(s.clockHighWater) {
		s.clockRollback = true
		return true
	}
	if now.After(s.clockHighWater) {
		s.clockHighWater = now
	}
	return false
}

// ClockRollbackDetected reports whether a wall-clock rollback was observed.
func (s *PolicyStore) ClockRollbackDetected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clockRollback
}

func (s *PolicyStore) persist(policy Policy) error {
	if !s.clockHighWater.IsZero() && s.clockHighWater.After(policy.ClockHighWaterUTC) {
		policy.ClockHighWaterUTC = s.clockHighWater
	}
	payload, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if len(payload) > maxPolicyBytes {
		return errors.New("titan policy payload too large")
	}
	return atomicWriteFile(s.path, payload)
}

func clonePolicy(policy Policy) Policy {
	clone := policy
	clone.Permits = append([]Permit(nil), policy.Permits...)
	clone.DevelopmentRoots = append([]string(nil), policy.DevelopmentRoots...)
	clone.OwnerProcessImages = append([]string(nil), policy.OwnerProcessImages...)
	return clone
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return false
		}
	}
	return true
}
