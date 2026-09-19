// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"errors"
	"net/netip"
	"sort"
)

type prefixTrieNode struct {
	terminal bool
	zero     *prefixTrieNode
	one      *prefixTrieNode
}

type prefixTrie struct {
	v4 *prefixTrieNode
	v6 *prefixTrieNode
}

func compileEnforcementIndicators(values []string, protected []netip.Prefix) ([]string, error) {
	blocks := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !validThreatPrefix(prefix) {
			return nil, errors.New("blocking indicator compilation rejected invalid prefix")
		}
		blocks = append(blocks, canonicalPrefix(prefix))
	}
	blocks = compactPrefixUnion(blocks)
	protected = compactPrefixUnion(protected)
	protectedTrie := buildPrefixTrie(protected)
	compiled := make([]netip.Prefix, 0, len(blocks))
	for _, block := range blocks {
		protectedNode, covered := protectedTrie.nodeFor(block)
		if covered {
			continue
		}
		if protectedNode == nil {
			compiled = append(compiled, block)
			continue
		}
		subtractProtected(block, protectedNode, &compiled)
		if len(compiled) > maximumEnforcementIndicators {
			return nil, errors.New("protected network subtraction exceeded enforcement boundary")
		}
	}
	compiled = compactPrefixUnion(compiled)
	if len(compiled) > maximumEnforcementIndicators {
		return nil, errors.New("compiled enforcement boundary exceeded")
	}
	return prefixStrings(compiled), nil
}

func compactPrefixUnion(prefixes []netip.Prefix) []netip.Prefix {
	trie := buildPrefixTrie(prefixes)
	result := make([]netip.Prefix, 0, len(prefixes))
	collectTriePrefixes(trie.v4, netip.MustParsePrefix("0.0.0.0/0"), &result)
	collectTriePrefixes(trie.v6, netip.MustParsePrefix("::/0"), &result)
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}

func prefixStrings(prefixes []netip.Prefix) []string {
	result := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.IsValid() {
			result = append(result, canonicalPrefix(prefix).String())
		}
	}
	sort.Strings(result)
	return result
}

func buildPrefixTrie(prefixes []netip.Prefix) prefixTrie {
	var trie prefixTrie
	for _, raw := range prefixes {
		prefix := canonicalPrefix(raw)
		if !prefix.IsValid() {
			continue
		}
		root := &trie.v6
		if prefix.Addr().Is4() {
			root = &trie.v4
		}
		if *root == nil {
			*root = &prefixTrieNode{}
		}
		insertPrefix(*root, prefix, 0)
	}
	return trie
}

func insertPrefix(node *prefixTrieNode, prefix netip.Prefix, depth int) {
	if node == nil || node.terminal {
		return
	}
	if depth == prefix.Bits() {
		node.terminal = true
		node.zero = nil
		node.one = nil
		return
	}
	if addressBit(prefix.Addr(), depth) == 0 {
		if node.zero == nil {
			node.zero = &prefixTrieNode{}
		}
		insertPrefix(node.zero, prefix, depth+1)
	} else {
		if node.one == nil {
			node.one = &prefixTrieNode{}
		}
		insertPrefix(node.one, prefix, depth+1)
	}
	if node.zero != nil && node.one != nil && node.zero.terminal && node.one.terminal {
		node.terminal = true
		node.zero = nil
		node.one = nil
	}
}

func collectTriePrefixes(node *prefixTrieNode, prefix netip.Prefix, result *[]netip.Prefix) {
	if node == nil {
		return
	}
	if node.terminal {
		*result = append(*result, canonicalPrefix(prefix))
		return
	}
	if prefix.Bits() >= prefix.Addr().BitLen() {
		return
	}
	left, right := splitPrefix(prefix)
	collectTriePrefixes(node.zero, left, result)
	collectTriePrefixes(node.one, right, result)
}

func (t prefixTrie) nodeFor(prefix netip.Prefix) (*prefixTrieNode, bool) {
	prefix = canonicalPrefix(prefix)
	if !prefix.IsValid() {
		return nil, false
	}
	node := t.v6
	if prefix.Addr().Is4() {
		node = t.v4
	}
	if node == nil {
		return nil, false
	}
	for depth := 0; depth < prefix.Bits(); depth++ {
		if node.terminal {
			return node, true
		}
		if addressBit(prefix.Addr(), depth) == 0 {
			node = node.zero
		} else {
			node = node.one
		}
		if node == nil {
			return nil, false
		}
	}
	if node.terminal {
		return node, true
	}
	return node, false
}

func subtractProtected(prefix netip.Prefix, protected *prefixTrieNode, result *[]netip.Prefix) {
	if protected == nil {
		*result = append(*result, canonicalPrefix(prefix))
		return
	}
	if protected.terminal {
		return
	}
	if prefix.Bits() >= prefix.Addr().BitLen() {
		*result = append(*result, canonicalPrefix(prefix))
		return
	}
	left, right := splitPrefix(prefix)
	subtractProtected(left, protected.zero, result)
	subtractProtected(right, protected.one, result)
}

func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	prefix = canonicalPrefix(prefix)
	bits := prefix.Bits()
	left := netip.PrefixFrom(prefix.Addr(), bits+1).Masked()
	if prefix.Addr().Is4() {
		bytes := prefix.Addr().As4()
		bytes[bits/8] |= byte(1 << (7 - uint(bits%8)))
		right := netip.PrefixFrom(netip.AddrFrom4(bytes), bits+1).Masked()
		return left, right
	}
	bytes := prefix.Addr().As16()
	bytes[bits/8] |= byte(1 << (7 - uint(bits%8)))
	right := netip.PrefixFrom(netip.AddrFrom16(bytes), bits+1).Masked()
	return left, right
}

func canonicalPrefix(prefix netip.Prefix) netip.Prefix {
	if !prefix.IsValid() {
		return netip.Prefix{}
	}
	address := prefix.Addr().Unmap()
	bits := prefix.Bits()
	if prefix.Addr().Is4In6() {
		bits -= 96
	}
	if bits < 0 || bits > address.BitLen() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(address, bits).Masked()
}

func addressBit(address netip.Addr, bit int) byte {
	address = address.Unmap()
	if bit < 0 || bit >= address.BitLen() {
		return 0
	}
	if address.Is4() {
		bytes := address.As4()
		return (bytes[bit/8] >> (7 - uint(bit%8))) & 1
	}
	bytes := address.As16()
	return (bytes[bit/8] >> (7 - uint(bit%8))) & 1
}
