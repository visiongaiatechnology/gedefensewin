// STATUS: PLATIN
package main

import "testing"

func TestFilterBlockNotificationsDropsNonBlockKinds(t *testing.T) {
	events := []controlNotification{
		{ID: "block-1", Kind: "BLOCK", Title: "Malware blockiert", Detail: "MHX"},
		{ID: "titan-1", Kind: "TITAN_BLOCK", Title: "Titan: Objekt isoliert", Detail: "Quarantäne"},
		{ID: "audit-1", Kind: "DEFENDER", Title: "Defender-Konfiguration", Detail: "audit"},
		{ID: "kinetic-1", Kind: "KINETIC", Title: "Burst", Detail: "correlation"},
		{ID: "", Kind: "BLOCK", Title: "ignored empty id"},
	}
	next := filterBlockNotifications(events, true, "LOW")
	if len(next) != 2 || next[0].ID != "block-1" || next[1].ID != "titan-1" {
		t.Fatalf("non-block events leaked into native notifications: %+v", next)
	}
}

func TestFilterBlockNotificationsHonorsToastPreferences(t *testing.T) {
	events := []controlNotification{
		{ID: "low", Kind: "BLOCK", Severity: "LOW", Title: "low"},
		{ID: "high", Kind: "BLOCK", Severity: "HIGH", Title: "high"},
		{ID: "critical", Kind: "BLOCK", Severity: "CRITICAL", Title: "critical"},
	}
	if next := filterBlockNotifications(events, false, "LOW"); len(next) != 0 {
		t.Fatalf("disabled Windows toasts still produced entries: %+v", next)
	}
	next := filterBlockNotifications(events, true, "HIGH")
	if len(next) != 2 || next[0].ID != "high" || next[1].ID != "critical" {
		t.Fatalf("minimum toast severity was not applied: %+v", next)
	}
}

func TestFilterBlockNotificationsPreservesNewestFirstOrder(t *testing.T) {
	events := []controlNotification{
		{ID: "new", Kind: "BLOCK", Title: "new"},
		{ID: "old", Kind: "BLOCK", Title: "old"},
	}
	next := filterBlockNotifications(events, true, "LOW")
	if len(next) != 2 || next[0].ID != "new" || next[1].ID != "old" {
		t.Fatalf("newest-first order was not preserved: %+v", next)
	}
}
