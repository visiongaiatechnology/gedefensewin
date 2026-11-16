// STATUS: PLATIN VGT SUPREME

// Package trust answers one question for the security engines: is this path a
// member of the installed, administrator-owned product tree? It exists because
// substring matching on a marker such as `\vgt\gedefense\` can be satisfied by
// any unprivileged user (for example `%TEMP%\vgt\gedefense\payload.exe`) and
// therefore granted a complete self-protection exemption. An install anchor
// plus a reparse-free path proof cannot be forged that way.
package trust

import (
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
)

const (
	defaultCacheEntries = 4096
	minimumTTL          = 5 * time.Second
)

// Resolver proves that a candidate path is safe to interpret as the file it
// names: absolute, on a local fixed drive, and free of symlink/junction
// redirection. It is injected so this package stays platform-neutral and
// testable.
type Resolver func(path string) error

type cacheEntry struct {
	trusted bool
	expires time.Time
}

// Verifier caches resolver decisions for paths inside one install anchor. The
// cache is bounded and entries expire so a directory swap cannot grant trust
// indefinitely.
type Verifier struct {
	anchor  product.InstallAnchor
	resolve Resolver
	ttl     time.Duration
	max     int
	now     func() time.Time

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// NewVerifier builds a verifier for one install anchor. A zero anchor or a nil
// resolver produces a verifier that denies every path (fail-closed).
func NewVerifier(anchor product.InstallAnchor, resolve Resolver, ttl time.Duration) *Verifier {
	if ttl < minimumTTL {
		ttl = minimumTTL
	}
	return &Verifier{
		anchor:  anchor,
		resolve: resolve,
		ttl:     ttl,
		max:     defaultCacheEntries,
		now:     time.Now,
		cache:   make(map[string]cacheEntry),
	}
}

// Enabled reports whether this verifier can ever return true.
func (v *Verifier) Enabled() bool {
	return v != nil && v.resolve != nil && v.anchor.Valid()
}

// TrustedTreePath reports whether path lies inside the installed product tree
// and resolves without a reparse-point redirect. Any resolver error denies
// trust. Results are cached per normalised path for a short, bounded time.
func (v *Verifier) TrustedTreePath(path string) bool {
	if !v.Enabled() {
		return false
	}
	if !v.anchor.Contains(path) {
		return false
	}
	key := strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(path), `"`)))
	now := v.now()
	v.mu.RLock()
	entry, cached := v.cache[key]
	v.mu.RUnlock()
	if cached && now.Before(entry.expires) {
		return entry.trusted
	}
	trusted := v.resolve(path) == nil
	v.mu.Lock()
	if len(v.cache) >= v.max {
		// Bounded memory: dropping the whole cache is cheap and cannot grow. A
		// trust decision is never extended by this reset, only forgotten.
		v.cache = make(map[string]cacheEntry, v.max)
	}
	v.cache[key] = cacheEntry{trusted: trusted, expires: now.Add(v.ttl)}
	v.mu.Unlock()
	return trusted
}
