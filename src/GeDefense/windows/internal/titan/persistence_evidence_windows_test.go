// STATUS: PLATIN VGT SUPREME
//go:build windows

package titan

import (
	"context"
	"strings"
	"testing"
)

// FIND-WIN-010: scanPersistence must attach the deterministic service-image
// evidence (resolved ImagePath, configured start type, Authenticode status) to
// every changed/added service observation instead of emitting an empty actor.
func TestPersistenceObservationsCarryServiceImageEvidence(t *testing.T) {
	withTitanSignatureVerifier(t, alwaysValidSignatureVerifier)
	engine := newTestEngine(t)
	ctx := context.Background()
	engine.scanPersistence(ctx)

	baseline, err := engine.loadBaseline()
	if err != nil {
		t.Fatalf("baseline load: %v", err)
	}
	currentServices, definitions := collectServices()

	var targetName, targetImage string
	for name, fingerprint := range currentServices {
		definition := definitions[name]
		executable := titanResolveServiceExecutable(definition.ImagePath)
		parts := strings.Split(fingerprint, "|")
		if executable == "" || len(parts) != 4 {
			continue
		}
		if titanPersistenceImageHash(executable) == "" {
			// Some services point at unreadable or oversized images; the
			// evidence contract only guarantees a hash when the image can
			// actually be read. Select a hashable service so the assertion is
			// deterministic instead of depending on map iteration order.
			continue
		}
		targetName, targetImage = name, executable
		// Mutate only the ImagePath part of the fingerprint so the diff classifies
		// the change as IMAGE_PATH and the actor evidence is populated from the
		// service definition that is read during the scan.
		changed := append([]string(nil), parts...)
		changed[0] = "tampered-service-image-path"
		baseline.Services[name] = strings.Join(changed, "|")
		break
	}
	if targetName == "" {
		t.Skip("no service with a resolvable ImagePath available on this host")
	}
	if err := engine.saveBaseline(baseline); err != nil {
		t.Fatalf("baseline save: %v", err)
	}
	engine.scanPersistence(ctx)

	events, _, err := engine.Events(100, 0, FilterAll)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	var found *Event
	for index := range events {
		event := events[index]
		if event.Type == EventPersistenceChanged && event.Object.Kind == ObjectService && event.Object.Name == targetName {
			found = &events[index]
			break
		}
	}
	if found == nil {
		// The changed service may be older than the newest page; page backwards.
		for offset := 100; offset < 10000; offset += 100 {
			batch, total, batchErr := engine.Events(100, offset, FilterAll)
			if batchErr != nil {
				t.Fatalf("events page %d: %v", offset, batchErr)
			}
			for index := range batch {
				event := batch[index]
				if event.Type == EventPersistenceChanged && event.Object.Kind == ObjectService && event.Object.Name == targetName {
					found = &batch[index]
					break
				}
			}
			if found != nil || offset+100 >= total {
				break
			}
		}
	}
	if found == nil {
		t.Fatalf("no persistence event for tampered service %s", targetName)
	}
	if !strings.EqualFold(found.Actor.Path, targetImage) {
		t.Fatalf("observation actor path=%q, want resolved service image %q", found.Actor.Path, targetImage)
	}
	if !strings.EqualFold(found.Actor.Image, titanPathBase(targetImage)) {
		t.Fatalf("observation actor image=%q, want %q", found.Actor.Image, titanPathBase(targetImage))
	}
	if found.Object.SignatureStatus != signatureStatusValid {
		t.Fatalf("observation signature status=%q, want %q", found.Object.SignatureStatus, signatureStatusValid)
	}
	if found.Object.Change != "IMAGE_PATH" {
		t.Fatalf("observation change=%q, want IMAGE_PATH", found.Object.Change)
	}
	if !strings.Contains(found.Actor.CorrelationNote, "Registry") {
		t.Fatalf("actor note does not document the registry evidence: %q", found.Actor.CorrelationNote)
	}
	if found.Actor.SHA256 == "" {
		t.Fatal("service image hash was not recorded")
	}
}
