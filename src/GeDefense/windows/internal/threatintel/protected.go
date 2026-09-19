// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	protectedPolicySchemaVersion = 1
	maximumProtectedPrefixes     = 256
	minimumProtectedV4Bits       = 16
	minimumProtectedV6Bits       = 32
)

type ProtectedNetworkPolicy struct {
	UpdatedUTC       time.Time `json:"updatedUtc,omitempty"`
	GenerationSHA256 string    `json:"generationSha256"`
	Prefixes         []string  `json:"prefixes"`
}

type protectedPolicyDisk struct {
	SchemaVersion    int       `json:"schemaVersion"`
	UpdatedUTC       time.Time `json:"updatedUtc"`
	GenerationSHA256 string    `json:"generationSha256"`
	Prefixes         []string  `json:"prefixes"`
	MAC              string    `json:"mac"`
}

type protectedPolicyMACPayload struct {
	SchemaVersion    int       `json:"schemaVersion"`
	UpdatedUTC       time.Time `json:"updatedUtc"`
	GenerationSHA256 string    `json:"generationSha256"`
	Prefixes         []string  `json:"prefixes"`
}

func protectedPolicyPath(root string) string {
	return filepath.Join(root, "protected-network-policy.json")
}

func protectedPolicyKeyPath(root string) string {
	return filepath.Join(root, "protected-network-policy.key")
}

func loadOrCreateProtectedPolicyKey(root string) ([]byte, error) {
	path := protectedPolicyKeyPath(root)
	if raw, err := os.ReadFile(path); err == nil {
		key, decodeErr := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decodeErr != nil || len(key) != sha256.Size {
			return nil, errors.New("protected network policy key rejected")
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	key := make([]byte, sha256.Size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateProtectedPolicyKey(root)
	}
	if err != nil {
		return nil, err
	}
	encoded := []byte(base64.RawStdEncoding.EncodeToString(key) + "\n")
	_, writeErr := file.Write(encoded)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return nil, writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return nil, closeErr
	}
	return key, nil
}

func loadProtectedPolicy(root string, key []byte) (ProtectedNetworkPolicy, []netip.Prefix, error) {
	path := protectedPolicyPath(root)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		empty := protectedPolicyFromPrefixes(nil, time.Time{})
		return empty, nil, nil
	}
	if err != nil {
		return ProtectedNetworkPolicy{}, nil, err
	}
	if len(raw) < 2 || len(raw) > 64<<10 {
		return ProtectedNetworkPolicy{}, nil, errors.New("protected network policy size boundary rejected")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var disk protectedPolicyDisk
	if err := decoder.Decode(&disk); err != nil {
		return ProtectedNetworkPolicy{}, nil, errors.New("protected network policy JSON rejected")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ProtectedNetworkPolicy{}, nil, errors.New("protected network policy trailing data rejected")
	}
	if disk.SchemaVersion != protectedPolicySchemaVersion || disk.UpdatedUTC.IsZero() || len(disk.Prefixes) > maximumProtectedPrefixes || len(disk.GenerationSHA256) != 64 || len(disk.MAC) != 64 {
		return ProtectedNetworkPolicy{}, nil, errors.New("protected network policy metadata rejected")
	}
	prefixes, canonical, err := normalizeProtectedPrefixes(disk.Prefixes)
	if err != nil {
		return ProtectedNetworkPolicy{}, nil, err
	}
	generation := protectedPolicyGeneration(canonical)
	if !fixedHexEqual(generation, disk.GenerationSHA256) {
		return ProtectedNetworkPolicy{}, nil, errors.New("protected network policy generation rejected")
	}
	payload := protectedPolicyMACPayload{SchemaVersion: disk.SchemaVersion, UpdatedUTC: disk.UpdatedUTC.UTC(), GenerationSHA256: generation, Prefixes: canonical}
	expectedMAC, err := protectedPolicyMAC(key, payload)
	if err != nil || !fixedHexEqual(expectedMAC, disk.MAC) {
		return ProtectedNetworkPolicy{}, nil, errors.New("protected network policy authentication rejected")
	}
	policy := ProtectedNetworkPolicy{UpdatedUTC: disk.UpdatedUTC.UTC(), GenerationSHA256: generation, Prefixes: append([]string(nil), canonical...)}
	return policy, prefixes, nil
}

func writeProtectedPolicy(root string, key []byte, prefixes []netip.Prefix, updatedUTC time.Time) (ProtectedNetworkPolicy, error) {
	canonicalPrefixes := compactPrefixUnion(prefixes)
	canonical := prefixStrings(canonicalPrefixes)
	if len(canonical) > maximumProtectedPrefixes {
		return ProtectedNetworkPolicy{}, errors.New("protected network policy boundary exceeded")
	}
	policy := protectedPolicyFromStrings(canonical, updatedUTC.UTC())
	payload := protectedPolicyMACPayload{SchemaVersion: protectedPolicySchemaVersion, UpdatedUTC: policy.UpdatedUTC, GenerationSHA256: policy.GenerationSHA256, Prefixes: policy.Prefixes}
	mac, err := protectedPolicyMAC(key, payload)
	if err != nil {
		return ProtectedNetworkPolicy{}, err
	}
	disk := protectedPolicyDisk{SchemaVersion: protectedPolicySchemaVersion, UpdatedUTC: policy.UpdatedUTC, GenerationSHA256: policy.GenerationSHA256, Prefixes: policy.Prefixes, MAC: mac}
	raw, err := json.Marshal(disk)
	if err != nil {
		return ProtectedNetworkPolicy{}, err
	}
	if err := atomicWrite(protectedPolicyPath(root), append(raw, '\n')); err != nil {
		return ProtectedNetworkPolicy{}, err
	}
	return policy, nil
}

func normalizeProtectedPrefixes(values []string) ([]netip.Prefix, []string, error) {
	if len(values) > maximumProtectedPrefixes {
		return nil, nil, errors.New("protected network prefix boundary exceeded")
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := parseProtectedPrefix(value)
		if err != nil {
			return nil, nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	prefixes = compactPrefixUnion(prefixes)
	if len(prefixes) > maximumProtectedPrefixes {
		return nil, nil, errors.New("protected network prefix boundary exceeded")
	}
	return prefixes, prefixStrings(prefixes), nil
}

func parseProtectedPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 49 || !isThreatToken(value) {
		return netip.Prefix{}, errors.New("protected network prefix rejected")
	}
	var prefix netip.Prefix
	if strings.IndexByte(value, '/') >= 0 {
		parsed, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, errors.New("protected network prefix rejected")
		}
		prefix = parsed
	} else {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, errors.New("protected network address rejected")
		}
		address = address.Unmap()
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	prefix = canonicalPrefix(prefix)
	if !prefix.IsValid() {
		return netip.Prefix{}, errors.New("protected network prefix rejected")
	}
	address := prefix.Addr()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return netip.Prefix{}, errors.New("protected network prefix must be public unicast")
	}
	minimum := minimumProtectedV6Bits
	if address.Is4() {
		minimum = minimumProtectedV4Bits
	}
	if prefix.Bits() < minimum {
		return netip.Prefix{}, errors.New("protected network prefix is too broad")
	}
	for _, reserved := range protectedThreatRanges {
		if prefixesOverlap(prefix, reserved) {
			return netip.Prefix{}, errors.New("protected network prefix overlaps reserved address space")
		}
	}
	return prefix, nil
}

func protectedPolicyFromPrefixes(prefixes []netip.Prefix, updatedUTC time.Time) ProtectedNetworkPolicy {
	return protectedPolicyFromStrings(prefixStrings(compactPrefixUnion(prefixes)), updatedUTC)
}

func protectedPolicyFromStrings(prefixes []string, updatedUTC time.Time) ProtectedNetworkPolicy {
	canonical := append([]string(nil), prefixes...)
	sort.Strings(canonical)
	return ProtectedNetworkPolicy{UpdatedUTC: updatedUTC.UTC(), GenerationSHA256: protectedPolicyGeneration(canonical), Prefixes: canonical}
}

func protectedPolicyGeneration(prefixes []string) string {
	digest := sha256.Sum256([]byte("VGT-GEDEFENSE-PROTECTED-NETWORKS-V1\n" + strings.Join(prefixes, "\n")))
	return hex.EncodeToString(digest[:])
}

func protectedPolicyMAC(key []byte, payload protectedPolicyMACPayload) (string, error) {
	if len(key) != sha256.Size {
		return "", errors.New("protected network policy key rejected")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func fixedHexEqual(left, right string) bool {
	leftBytes, leftErr := hex.DecodeString(left)
	rightBytes, rightErr := hex.DecodeString(right)
	if leftErr != nil || rightErr != nil || len(leftBytes) != sha256.Size || len(rightBytes) != sha256.Size {
		return false
	}
	return hmac.Equal(leftBytes, rightBytes)
}
