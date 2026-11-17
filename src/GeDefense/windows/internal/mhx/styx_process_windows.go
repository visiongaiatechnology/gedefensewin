// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	styxProcessCacheMax = 2048
	styxProcessCacheTTL = 60 * time.Second
)

type styxProcessInfo struct {
	Name      string
	Path      string
	ExpiresAt time.Time
}

type styxProcessResolver struct {
	mu    sync.Mutex
	cache map[int]styxProcessInfo
	now   func() time.Time
}

func newStyxProcessResolver(now func() time.Time) *styxProcessResolver {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &styxProcessResolver{
		cache: make(map[int]styxProcessInfo, 128),
		now:   now,
	}
}

func (r *styxProcessResolver) Resolve(pid int) (string, string) {
	if pid <= 0 {
		return "", ""
	}
	if pid == 4 {
		return "System", `C:\Windows\System32\ntoskrnl.exe`
	}
	now := r.now()
	if r != nil {
		r.mu.Lock()
		if entry, ok := r.cache[pid]; ok && now.Before(entry.ExpiresAt) {
			r.mu.Unlock()
			return entry.Name, entry.Path
		}
		r.mu.Unlock()
	}

	name, fullPath := "", ""
	identity, err := winapi.OpenProcessIdentity(uint32(pid), false)
	if err == nil {
		fullPath = sanitizeStyxProcessPath(identity.ImagePath)
		_ = identity.Close()
		if fullPath != "" {
			name = sanitizeStyxProcess(filepath.Base(fullPath))
			if name == "" {
				name = truncate(filepath.Base(fullPath), styMaxProcessName)
			}
		}
	}

	if r != nil {
		r.mu.Lock()
		if len(r.cache) >= styxProcessCacheMax {
			for k, v := range r.cache {
				if !now.Before(v.ExpiresAt) {
					delete(r.cache, k)
				}
			}
			if len(r.cache) >= styxProcessCacheMax {
				for k := range r.cache {
					delete(r.cache, k)
					break
				}
			}
		}
		r.cache[pid] = styxProcessInfo{
			Name:      name,
			Path:      fullPath,
			ExpiresAt: now.Add(styxProcessCacheTTL),
		}
		r.mu.Unlock()
	}
	return name, fullPath
}
