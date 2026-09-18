// STATUS: DIAMANT VGT SUPREME
package mhx

import "time"

type dedupeEntry struct {
	key    string
	expiry time.Time
}

type boundedDedupe struct {
	entries []dedupeEntry
	index   map[string]int
	next    int
}

func newBoundedDedupe(capacity int) *boundedDedupe {
	if capacity < 1 {
		capacity = 1
	}
	return &boundedDedupe{
		entries: make([]dedupeEntry, 0, capacity),
		index:   make(map[string]int, capacity),
	}
}

// Admit returns true exactly when the key should be emitted. The structure is
// strictly bounded and uses round-robin eviction once full, so cardinality
// pressure can reduce deduplication efficiency but can never blind telemetry to
// every new key until an expiry sweep completes.
func (d *boundedDedupe) Admit(key string, now time.Time, ttl time.Duration) bool {
	if key == "" || ttl <= 0 {
		return false
	}
	if slot, exists := d.index[key]; exists {
		entry := &d.entries[slot]
		if now.Before(entry.expiry) {
			return false
		}
		entry.expiry = now.Add(ttl)
		return true
	}

	entry := dedupeEntry{key: key, expiry: now.Add(ttl)}
	if len(d.entries) < cap(d.entries) {
		d.index[key] = len(d.entries)
		d.entries = append(d.entries, entry)
		return true
	}

	if len(d.entries) == 0 {
		return false
	}
	slot := d.next % len(d.entries)
	delete(d.index, d.entries[slot].key)
	d.entries[slot] = entry
	d.index[key] = slot
	d.next = (slot + 1) % len(d.entries)
	return true
}
