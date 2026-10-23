// STATUS: DIAMANT VGT SUPREME
package hardening

import (
	"regexp"
	"testing"
)

func TestCatalogMetadataIsStable(t *testing.T) {
	catalog := Catalog()
	if len(catalog) != 12 {
		t.Fatalf("catalog size = %d, want 12", len(catalog))
	}
	expectedOrder := []string{"DefenderCloud", "ASR", "ControlledFolderAccess", "Firewall", "CredentialGuard", "MemoryIntegrity", "LSASS", "SMB", "PowerShellLogging", "UAC", "USBStorage", "RemoteDesktop"}
	rebootRequired := map[string]bool{"CredentialGuard": true, "MemoryIntegrity": true, "LSASS": true, "SMB": true}
	seen := make(map[string]struct{}, len(catalog))
	for index, definition := range catalog {
		if definition.ID != expectedOrder[index] {
			t.Fatalf("catalog[%d].ID = %q, want %q", index, definition.ID, expectedOrder[index])
		}
		if _, duplicate := seen[definition.ID]; duplicate {
			t.Fatalf("duplicate catalog ID %q", definition.ID)
		}
		seen[definition.ID] = struct{}{}
		if definition.Label == "" || definition.Category == "" || definition.Description == "" {
			t.Fatalf("catalog metadata incomplete: %+v", definition)
		}
		if len(definition.SupportedModes) != 4 {
			t.Fatalf("SupportedModes = %v", definition.SupportedModes)
		}
		if definition.ConfigurableFields == nil {
			t.Fatalf("%s ConfigurableFields must serialize as an array", definition.ID)
		}
		if definition.RebootRequired != rebootRequired[definition.ID] {
			t.Fatalf("%s RebootRequired = %v", definition.ID, definition.RebootRequired)
		}
	}
}

func TestCatalogCoversMeasuredComponentStatus(t *testing.T) {
	catalog := Catalog()
	statuses := componentsFromResult(Result{})
	if len(statuses) != len(catalog) {
		t.Fatalf("status size = %d, catalog size = %d", len(statuses), len(catalog))
	}
	definitions := make(map[string]ComponentDefinition, len(catalog))
	for _, definition := range catalog {
		definitions[definition.ID] = definition
	}
	for _, status := range statuses {
		definition, ok := definitions[status.ID]
		if !ok {
			t.Fatalf("component %s missing from catalog", status.ID)
		}
		if status.Name != definition.Label {
			t.Fatalf("%s label = %q vs catalog %q", status.ID, status.Name, definition.Label)
		}
		if status.Category != definition.Category {
			t.Fatalf("%s category = %q vs catalog %q", status.ID, status.Category, definition.Category)
		}
		if status.Active {
			t.Fatalf("%s reported active without measured state", status.ID)
		}
	}
}

func TestCatalogIsDefensiveCopy(t *testing.T) {
	first := Catalog()
	first[0].Label = "mutated"
	first[0].SupportedModes[0] = "mutated"
	first[0].ConfigurableFields[0].Label = "mutated"
	first[0].ConfigurableFields[0].Values[0] = "mutated"
	second := Catalog()
	if second[0].Label == "mutated" || second[0].SupportedModes[0] == "mutated" || second[0].ConfigurableFields[0].Label == "mutated" || second[0].ConfigurableFields[0].Values[0] == "mutated" {
		t.Fatal("catalog returned aliased internal state")
	}
}

func TestCatalogConfigurableFieldsMatchSettingsSchema(t *testing.T) {
	catalog := Catalog()
	fields := make(map[string]struct{})
	for _, definition := range catalog {
		for _, field := range definition.ConfigurableFields {
			fields[field.Key] = struct{}{}
			if field.Label == "" || field.Description == "" {
				t.Fatalf("configurable field metadata incomplete: %+v", field)
			}
		}
	}
	for _, key := range []string{
		"defender.cloudBlockLevel",
		"defender.mapsReporting",
		"defender.submitSamplesConsent",
		"defender.networkProtection",
		"defender.puaProtection",
		"defender.controlledFolderAccess",
		"defender.asrRules",
		"firewall.profiles",
	} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("configurable field %q missing from catalog", key)
		}
	}
	asrFields := componentFieldByKey(t, "ASR", "defender.asrRules")
	if len(asrFields.ItemFields) != 2 {
		t.Fatalf("ASR item fields = %+v", asrFields.ItemFields)
	}
	firewallFields := componentFieldByKey(t, "Firewall", "firewall.profiles")
	if len(firewallFields.ItemFields) != 9 {
		t.Fatalf("firewall item fields = %+v", firewallFields.ItemFields)
	}
}

func componentFieldByKey(t *testing.T, componentID, key string) ConfigField {
	t.Helper()
	for _, definition := range Catalog() {
		if definition.ID != componentID {
			continue
		}
		for _, field := range definition.ConfigurableFields {
			if field.Key == key {
				return field
			}
		}
	}
	t.Fatalf("component %s has no configurable field %s", componentID, key)
	return ConfigField{}
}

func TestASRRuleCatalogStable(t *testing.T) {
	rules := ASRRuleCatalog()
	if len(rules) != 11 {
		t.Fatalf("ASR rule catalog size = %d", len(rules))
	}
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if !pattern.MatchString(rule.ID) {
			t.Fatalf("invalid ASR rule ID %q", rule.ID)
		}
		if rule.Label == "" {
			t.Fatalf("ASR rule %s has no label", rule.ID)
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			t.Fatalf("duplicate ASR rule %s", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
}

func TestSettingsCatalogCoversApplySchema(t *testing.T) {
	groups := SettingsCatalog()
	if len(groups) != 3 {
		t.Fatalf("settings groups = %d", len(groups))
	}
	byID := make(map[string]SettingsGroup, len(groups))
	for _, group := range groups {
		if group.ID == "" || group.Label == "" || group.Description == "" {
			t.Fatalf("settings group metadata incomplete: %+v", group)
		}
		byID[group.ID] = group
	}
	defender := byID["defender"]
	keys := make(map[string]struct{}, len(defender.Fields))
	for _, field := range defender.Fields {
		keys[field.Key] = struct{}{}
	}
	for _, key := range []string{"cloudBlockLevel", "mapsReporting", "submitSamplesConsent", "networkProtection", "puaProtection", "controlledFolderAccess", "asrRules"} {
		if _, ok := keys[key]; !ok {
			t.Fatalf("defender settings key %q missing", key)
		}
	}
	firewall := byID["firewall"]
	if len(firewall.Fields) != 1 || len(firewall.Fields[0].ItemFields) != 9 {
		t.Fatalf("firewall settings schema = %+v", firewall.Fields)
	}
	components := byID["components"]
	if len(components.Fields) != 1 || len(components.Fields[0].Values) != 12 {
		t.Fatalf("component settings schema = %+v", components.Fields)
	}
}

func TestEngineCatalogMethod(t *testing.T) {
	engine := &Engine{}
	if catalog := engine.Catalog(); len(catalog) != 12 {
		t.Fatalf("engine catalog size = %d", len(catalog))
	}
}
