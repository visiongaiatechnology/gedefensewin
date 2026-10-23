package app

import "testing"

func TestDefenderSettingsMapsSupportedFieldsAndRejectsUnknown(t *testing.T) {
	values := map[string]any{
		"cloudBlockLevel": "highplus", "sampleSubmission": "safe",
		"networkProtection": true, "puaProtection": false, "controlledFolderAccess": true,
	}
	config, err := defenderSettings(values, map[string]bool{
		"cloudBlockLevel": true, "sampleSubmission": true, "networkProtection": true,
		"puaProtection": true, "controlledFolderAccess": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.CloudBlockLevel == nil || *config.CloudBlockLevel != "HighPlus" {
		t.Fatalf("cloud level mapping: %+v", config.CloudBlockLevel)
	}
	if config.SubmitSamplesConsent == nil || *config.SubmitSamplesConsent != "SendSafeSamples" {
		t.Fatalf("sample mapping: %+v", config.SubmitSamplesConsent)
	}
	if config.NetworkProtection == nil || *config.NetworkProtection != "Enabled" {
		t.Fatalf("network mapping: %+v", config.NetworkProtection)
	}
	if _, err := defenderSettings(values, map[string]bool{"realtimeProtection": true}); err == nil {
		t.Fatal("unsupported Defender field was accepted")
	}
}

func TestFirewallSettingsBuildsProfiles(t *testing.T) {
	config, err := firewallSettings(map[string]any{
		"domainProfileEnabled": true, "privateProfileEnabled": true, "publicProfileEnabled": true,
		"defaultInboundAction": "block", "notificationsEnabled": false, "loggingEnabled": true,
	}, map[string]bool{
		"domainProfileEnabled": true, "privateProfileEnabled": true, "publicProfileEnabled": true,
		"defaultInboundAction": true, "notificationsEnabled": true, "loggingEnabled": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Profiles) != 3 {
		t.Fatalf("profiles=%d", len(config.Profiles))
	}
	for _, profile := range config.Profiles {
		if profile.Enabled == nil || !*profile.Enabled {
			t.Fatalf("%s not enabled", profile.Name)
		}
		if profile.DefaultInboundAction == nil || *profile.DefaultInboundAction != "Block" {
			t.Fatalf("%s inbound action", profile.Name)
		}
		if profile.NotifyOnListen == nil || *profile.NotifyOnListen {
			t.Fatalf("%s notification mapping", profile.Name)
		}
		if profile.LogBlocked == nil || !*profile.LogBlocked {
			t.Fatalf("%s logging mapping", profile.Name)
		}
	}
}

func TestASRRulesRequireCanonicalUUIDs(t *testing.T) {
	if _, err := asrRules([]any{"56a863a9-875e-4185-98a7-b882c64b5ce5:block"}); err != nil {
		t.Fatal(err)
	}
	if _, err := asrRules([]any{"friendly-name:block"}); err == nil {
		t.Fatal("alias was accepted as a canonical rule ID")
	}
}

func TestChangedFieldsUsesCanonicalPrefix(t *testing.T) {
	changed := changedFields([]string{"defender.cloudBlockLevel", "kinetic.minEvents", "mhx.autoTerminate"}, "defender")
	if !changed["cloudBlockLevel"] || len(changed) != 1 {
		t.Fatalf("changed=%v", changed)
	}
}
