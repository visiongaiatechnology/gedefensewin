package hardening

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The built-in Enterprise Balanced profile must never silently select Defender
// audit mode. A profile labelled as balanced/enforced has to enable ASR and CFA;
// otherwise the UI presents an "active" hardening state that does not block.
func TestEnterpriseBalancedProfileEnforcesASRAndCFA(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	root := filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "..")
	path := filepath.Join(root, "engine", "profiles", "enterprise-balanced.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read EnterpriseBalanced profile: %v", err)
	}
	var profile struct {
		ASRMode                string `json:"asrMode"`
		ControlledFolderAccess string `json:"controlledFolderAccess"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatalf("decode EnterpriseBalanced profile: %v", err)
	}
	if profile.ASRMode != "Enabled" {
		t.Fatalf("asrMode = %q, want Enabled", profile.ASRMode)
	}
	if profile.ControlledFolderAccess != "Enabled" {
		t.Fatalf("controlledFolderAccess = %q, want Enabled", profile.ControlledFolderAccess)
	}
}
