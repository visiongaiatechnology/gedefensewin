// STATUS: DIAMANT VGT SUPREME
package hardening

import "testing"

func TestComponentStatusDerivesFromMeasuredState(t *testing.T) {
	result := Result{CloudProtection: true, NetworkProtection: true, RealTimeProtection: true, ASRRules: 11, ASRBlockRules: 11, ControlledFolderAccess: true, Firewall: true, CredentialGuard: true, MemoryIntegrity: true, VulnerableDriverBlocklist: true, LSAProtection: true, SMBHardening: true, PowerShellLogging: true, UACSecureDesktop: true, USBStorageBlocked: true, RemoteDesktopDisabled: true}
	components := componentsFromResult(result)
	if len(components) != 12 {
		t.Fatalf("got %d components, want 12", len(components))
	}
	for _, component := range components {
		if !component.Active {
			t.Fatalf("component %s was not derived as active", component.ID)
		}
	}
}

func TestASRRequiresCompleteBlockSet(t *testing.T) {
	components := componentsFromResult(Result{ASRRules: 11, ASRBlockRules: 1})
	for _, component := range components {
		if component.ID == "ASR" && component.Active {
			t.Fatal("partial ASR block set was reported as fully active")
		}
	}
}
