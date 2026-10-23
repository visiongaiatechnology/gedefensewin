// STATUS: PLATIN
//go:build windows

package wintray

import "testing"

func TestNextNativeNotificationSuppressesHistoricalReplay(t *testing.T) {
	entries := []Notification{{ID: "new-2"}, {ID: "old-1"}}
	selected, show, next := nextNativeNotification(entries, false, "")
	if show || selected.ID != "" || next != "new-2" {
		t.Fatalf("first poll must prime without replay: selected=%+v show=%v next=%q", selected, show, next)
	}
}

func TestNextNativeNotificationShowsOnlyNewestUnseenBlock(t *testing.T) {
	entries := []Notification{{ID: "new-2", Title: "Blocked"}, {ID: "old-1"}}
	selected, show, next := nextNativeNotification(entries, true, "old-1")
	if !show || selected.ID != "new-2" || next != "new-2" {
		t.Fatalf("unexpected notification decision: selected=%+v show=%v next=%q", selected, show, next)
	}
}

func TestNextNativeNotificationIgnoresSeenAndEmptyEntries(t *testing.T) {
	if _, show, next := nextNativeNotification([]Notification{{ID: "same"}}, true, "same"); show || next != "same" {
		t.Fatalf("seen notification must not be repeated")
	}
	if _, show, next := nextNativeNotification(nil, true, "same"); show || next != "same" {
		t.Fatalf("empty feed must preserve cursor")
	}
	if _, show, next := nextNativeNotification([]Notification{{ID: ""}}, true, "same"); show || next != "same" {
		t.Fatalf("empty id must preserve cursor")
	}
}

func TestTruncateTextRespectsRunes(t *testing.T) {
	if got := truncateText("Grüße", 3); got != "Grü" {
		t.Fatalf("unexpected truncation: %q", got)
	}
	if got := truncateText("ok", 8); got != "ok" {
		t.Fatalf("short text changed: %q", got)
	}
}
