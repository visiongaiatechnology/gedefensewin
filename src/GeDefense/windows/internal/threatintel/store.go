// STATUS: DIAMANT VGT SUPREME
package threatintel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func sourceSnapshotPath(root, key string) string {
	return filepath.Join(root, "sources", key+".json")
}

func enforcementSnapshotPath(root string) string {
	return filepath.Join(root, "threat-intelligence-enforcement.json")
}

func writeSourceSnapshot(root string, snapshot sourceSnapshot) error {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return atomicWrite(sourceSnapshotPath(root, snapshot.Key), append(payload, '\n'))
}

func readSourceSnapshot(root string, source Source) (sourceSnapshot, error) {
	payload, err := os.ReadFile(sourceSnapshotPath(root, source.Key))
	if err != nil {
		return sourceSnapshot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshot sourceSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return sourceSnapshot{}, errors.New("cached threat source JSON rejected")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return sourceSnapshot{}, errors.New("cached threat source trailing data rejected")
	}
	if snapshot.SchemaVersion != SchemaVersion || snapshot.Key != source.Key || snapshot.Action != source.Action || snapshot.GeneratedUTC.IsZero() || len(snapshot.Indicators) == 0 || len(snapshot.Indicators) > maximumSourceIndicators {
		return sourceSnapshot{}, errors.New("cached threat source metadata rejected")
	}
	canonical := make([]string, 0, len(snapshot.Indicators))
	for _, value := range snapshot.Indicators {
		prefix, err := parseThreatToken(value)
		if err != nil {
			return sourceSnapshot{}, errors.New("cached threat source indicator rejected")
		}
		canonical = append(canonical, prefix.String())
	}
	sort.Strings(canonical)
	if digestIndicators(source.Key, source.Action, canonical) != snapshot.GenerationSHA256 {
		return sourceSnapshot{}, errors.New("cached threat source generation rejected")
	}
	snapshot.Indicators = canonical
	return snapshot, nil
}

func writeEnforcementSnapshot(root string, generatedUTC time.Time, index *Index, blockingFeeds int, policy ProtectedNetworkPolicy) error {
	if index == nil || index.blocking == 0 || index.blocking > maximumEnforcementIndicators || len(index.enforcementGeneration) != 64 || blockingFeeds <= 0 {
		return errors.New("threat enforcement snapshot rejected")
	}
	if len(policy.Prefixes) > maximumProtectedPrefixes || len(policy.GenerationSHA256) != 64 || !fixedHexEqual(policy.GenerationSHA256, protectedPolicyGeneration(policy.Prefixes)) {
		return errors.New("threat enforcement protection policy rejected")
	}
	snapshot := enforcementSnapshot{SchemaVersion: SchemaVersion, GeneratedUTC: generatedUTC.UTC(), GenerationSHA256: index.enforcementGeneration, ProtectionGenerationSHA256: policy.GenerationSHA256, ProtectedPrefixCount: len(policy.Prefixes), BlockIndicators: append([]string(nil), index.blockIndicators...), BlockingFeedCount: blockingFeeds}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return atomicWrite(enforcementSnapshotPath(root), append(payload, '\n'))
}

func digestIndicators(key string, action Action, indicators []string) string {
	digest := sha256.Sum256([]byte(key + "\n" + string(action) + "\n" + strings.Join(indicators, "\n")))
	return hex.EncodeToString(digest[:])
}
