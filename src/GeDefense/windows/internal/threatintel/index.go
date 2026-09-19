// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strings"
)

type indexEntry struct {
	action  Action
	sources []string
}

type Index struct {
	v4                    map[int]map[netip.Addr]indexEntry
	v6                    map[int]map[netip.Addr]indexEntry
	v4Lengths             []int
	v6Lengths             []int
	generation            string
	enforcementGeneration string
	indicators            int
	blocking              int
	correlation           int
	annotation            int
	rawBlockIndicators    []string
	blockIndicators       []string
}

type mutableEntry struct {
	action  Action
	sources map[string]struct{}
}

func buildIndex(snapshots map[string]sourceSnapshot) *Index {
	entries := make(map[netip.Prefix]*mutableEntry, 8192)
	for key, snapshot := range snapshots {
		for _, value := range snapshot.Indicators {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !validThreatPrefix(prefix) {
				continue
			}
			prefix = prefix.Masked()
			entry := entries[prefix]
			if entry == nil {
				entry = &mutableEntry{action: snapshot.Action, sources: make(map[string]struct{}, 2)}
				entries[prefix] = entry
			}
			if snapshot.Action.rank() > entry.action.rank() {
				entry.action = snapshot.Action
			}
			entry.sources[key] = struct{}{}
		}
	}

	result := &Index{v4: make(map[int]map[netip.Addr]indexEntry), v6: make(map[int]map[netip.Addr]indexEntry)}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for prefix := range entries {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })

	var generation strings.Builder
	blockIndicators := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		mutable := entries[prefix]
		sources := make([]string, 0, len(mutable.sources))
		for key := range mutable.sources {
			sources = append(sources, key)
		}
		sort.Strings(sources)
		entry := indexEntry{action: mutable.action, sources: sources}
		address := prefix.Addr().Unmap()
		bits := prefix.Bits()
		if prefix.Addr().Is4In6() {
			bits -= 96
		}
		target := result.v6
		if address.Is4() {
			target = result.v4
		}
		bucket := target[bits]
		if bucket == nil {
			bucket = make(map[netip.Addr]indexEntry)
			target[bits] = bucket
		}
		bucket[netip.PrefixFrom(address, bits).Masked().Addr()] = entry
		result.indicators++
		switch mutable.action {
		case ActionBlock:
			blockIndicators = append(blockIndicators, prefix.String())
		case ActionCorrelateOnly:
			result.correlation++
		case ActionAnnotateOnly:
			result.annotation++
		}
		generation.WriteString(prefix.String())
		generation.WriteByte('|')
		generation.WriteString(string(mutable.action))
		generation.WriteByte('|')
		generation.WriteString(strings.Join(sources, ","))
		generation.WriteByte('\n')
	}
	result.v4Lengths = descendingKeys(result.v4)
	result.v6Lengths = descendingKeys(result.v6)
	globalDigest := sha256.Sum256([]byte(generation.String()))
	result.generation = hex.EncodeToString(globalDigest[:])
	sort.Strings(blockIndicators)
	result.rawBlockIndicators = blockIndicators
	if err := result.compileEnforcement(nil); err != nil {
		result.blocking = 0
		result.blockIndicators = nil
		result.enforcementGeneration = ""
	}
	return result
}

func (i *Index) compileEnforcement(protected []netip.Prefix) error {
	if i == nil {
		return nil
	}
	compiled, err := compileEnforcementIndicators(i.rawBlockIndicators, protected)
	if err != nil {
		return err
	}
	i.blockIndicators = compiled
	i.blocking = len(compiled)
	blockDigest := sha256.Sum256([]byte("VGT-GEDEFENSE-TI-BLOCK-V2\n" + strings.Join(compiled, "\n")))
	i.enforcementGeneration = hex.EncodeToString(blockDigest[:])
	return nil
}

func descendingKeys(values map[int]map[netip.Addr]indexEntry) []int {
	result := make([]int, 0, len(values))
	for bits := range values {
		result = append(result, bits)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(result)))
	return result
}

func (i *Index) Lookup(address netip.Addr) Match {
	if i == nil || !address.IsValid() {
		return Match{}
	}
	address = address.Unmap()
	buckets, lengths := i.v6, i.v6Lengths
	if address.Is4() {
		buckets, lengths = i.v4, i.v4Lengths
	}
	var (
		found   bool
		action  Action
		sources map[string]struct{}
	)
	for _, bits := range lengths {
		if bits > address.BitLen() {
			continue
		}
		candidate := netip.PrefixFrom(address, bits).Masked().Addr()
		entry, ok := buckets[bits][candidate]
		if !ok {
			continue
		}
		found = true
		if entry.action.rank() > action.rank() {
			action = entry.action
		}
		if sources == nil {
			sources = make(map[string]struct{}, len(entry.sources))
		}
		for _, source := range entry.sources {
			sources[source] = struct{}{}
		}
	}
	if !found {
		return Match{}
	}
	keys := make([]string, 0, len(sources))
	for key := range sources {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return Match{Found: true, Action: action, Sources: keys}
}
