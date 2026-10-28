// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"testing"
)

func TestLineageRejectsMasqueradedSystemBinary(t *testing.T) {
	breach, _ := CheckLineageBreach(`C:\Users\Public\svchost.exe`, `C:\Windows\System32\services.exe`)
	if !breach {
		t.Fatal("svchost.exe outside System32 must be a lineage breach")
	}
	breach, _ = CheckLineageBreach(`C:\Windows\System32\svchost.exe`, `C:\Users\Public\services.exe`)
	if !breach {
		t.Fatal("svchost.exe with a non-canonical services.exe parent must be a lineage breach")
	}
	breach, _ = CheckLineageBreach(`C:\Windows\System32\svchost.exe`, `C:\Windows\System32\services.exe`)
	if breach {
		t.Fatal("canonical svchost.exe from canonical services.exe must not breach")
	}
}

func TestLineageEventRejectsRenamedOriginalFilename(t *testing.T) {
	event := ProcessEvent{
		Image:             "svchost.exe",
		ImagePath:         `C:\Windows\System32\svchost.exe`,
		ParentImage:       "services.exe",
		ParentPath:        `C:\Windows\System32\services.exe`,
		OriginalImageName: "totally-not-svchost.exe",
	}
	if breach, _ := CheckLineageBreachEvent(event); !breach {
		t.Fatal("renamed system binary (PE OriginalFilename mismatch) must breach lineage")
	}
	event.OriginalImageName = "svchost.exe"
	if breach, _ := CheckLineageBreachEvent(event); breach {
		t.Fatal("matching PE OriginalFilename must not breach lineage")
	}
}

func TestLineageEventAncestryFallback(t *testing.T) {
	event := ProcessEvent{
		Image:       "svchost.exe",
		ImagePath:   `C:\Windows\System32\svchost.exe`,
		ParentImage: "services.exe",
		Ancestry: []ProcessIdentity{
			{PID: 600, Image: "services.exe", Path: `C:\Windows\System32\services.exe`},
		},
	}
	if breach, _ := CheckLineageBreachEvent(event); breach {
		t.Fatal("ancestry-verified canonical services.exe parent must not breach")
	}
	event.Ancestry[0].Path = `C:\Users\Public\services.exe`
	if breach, _ := CheckLineageBreachEvent(event); !breach {
		t.Fatal("ancestry parent outside System32 must breach")
	}
}

func TestIsAppAllowedEventRejectsTamperedSystemApp(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clean := ProcessEvent{
		Image:               "svchost.exe",
		ImagePath:           `C:\Windows\System32\svchost.exe`,
		SignerStatus:        "Valid",
		ImageVersionCompany: "Microsoft Corporation",
		OriginalImageName:   "svchost.exe",
	}
	allowed, _, system, _ := store.IsAppAllowedEvent(clean)
	if !allowed || !system {
		t.Fatalf("clean system app must be allowed, got allowed=%v system=%v", allowed, system)
	}

	renamed := clean
	renamed.OriginalImageName = "payload.exe"
	allowed, _, system, reason := store.IsAppAllowedEvent(renamed)
	if allowed || !system || reason == "" {
		t.Fatalf("renamed system app must be rejected with reason, got allowed=%v system=%v reason=%q", allowed, system, reason)
	}

	unsigned := clean
	unsigned.SignerStatus = "NotSigned"
	allowed, _, system, reason = store.IsAppAllowedEvent(unsigned)
	if allowed || !system || reason == "" {
		t.Fatalf("unsigned system app must be rejected with reason, got allowed=%v system=%v reason=%q", allowed, system, reason)
	}

	foreign := clean
	foreign.ImageVersionCompany = "Evil Corp"
	allowed, _, system, reason = store.IsAppAllowedEvent(foreign)
	if allowed || !system || reason == "" {
		t.Fatalf("foreign-published system app must be rejected with reason, got allowed=%v system=%v reason=%q", allowed, system, reason)
	}
}

func TestFairScoreForEventAddsProvenanceFactors(t *testing.T) {
	event := ProcessEvent{
		Image:             "chrome.exe",
		ImagePath:         `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		SignerStatus:      "NotSigned",
		OriginalImageName: "chrome.exe",
	}
	result := CalculateFairScoreForEvent(event, true, "Google Chrome", false, "", false, false, false, false)
	if result.Score < 20 || len(result.Factors) == 0 || result.StrikeEvent {
		t.Fatalf("unsigned whitelisted event must carry a provenance factor, got %+v", result)
	}

	renamed := event
	renamed.SignerStatus = "Valid"
	renamed.OriginalImageName = "totally-not-chrome.exe"
	result = CalculateFairScoreForEvent(renamed, true, "Google Chrome", true, "KD-SIG-01", false, false, false, false)
	if !result.StrikeEvent || result.Score < 75 {
		t.Fatalf("renamed+signature whitelisted event must reach strike threshold, got %+v", result)
	}

	clean := event
	clean.SignerStatus = "Valid"
	clean.ImageVersionCompany = "Google LLC"
	result = CalculateFairScoreForEvent(clean, true, "Google Chrome", false, "", false, false, false, false)
	if result.Score != 0 || result.StrikeEvent {
		t.Fatalf("clean whitelisted event must stay clean, got %+v", result)
	}
}
