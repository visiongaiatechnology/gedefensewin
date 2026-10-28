// STATUS: PLATIN
//go:build windows

package server

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The tests in this file exercise the authoritative SAM fallback against the
// real local group installed by the installer. They never fake a SAM answer: if
// the group is missing or the current user is not a member, the test skips
// honestly instead of asserting an environment-specific result.

// requireLocalOperatorGroup skips when the product's local operator group is not
// installed on this host and otherwise returns the group SID resolved from the
// SAM by name.
func requireLocalOperatorGroup(t *testing.T) string {
	t.Helper()
	sid, err := lookupAccountSIDByName(operatorGroupName)
	if err != nil || sid == "" {
		t.Skipf("local operator group %q unavailable on this host: %v", operatorGroupName, err)
	}
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		t.Fatalf("resolved operator group SID %q is not a local machine SID", sid)
	}
	return sid
}

// currentProcessSID returns the SID of the test process user through the same
// token path the broker uses.
func currentProcessSID(t *testing.T) string {
	t.Helper()
	peer, err := operatorPeerFromPID(uint32(os.Getpid()))
	if err != nil || peer.SID == "" {
		t.Skipf("process token identity unavailable in this environment: %v", err)
	}
	return peer.SID
}

// requireCurrentOperatorMembership skips unless the current user is a direct
// member of the installed operator group; it returns the pinned group SID and the
// current user SID.
func requireCurrentOperatorMembership(t *testing.T) (string, string) {
	t.Helper()
	groupSID := requireLocalOperatorGroup(t)
	userSID := currentProcessSID(t)
	members, err := localGroupMemberSIDs(operatorGroupName)
	if err != nil {
		t.Fatalf("enumerate operator group members: %v", err)
	}
	if !containsSID(members, userSID) {
		t.Skipf("current user %q is not a direct member of the installed operator group on this host", userSID)
	}
	return groupSID, userSID
}

// TestLocalGroupContainsCurrentUserSID proves the SAM helper against the real
// local group: the current process user SID is reported as a member.
func TestLocalGroupContainsCurrentUserSID(t *testing.T) {
	_, userSID := requireCurrentOperatorMembership(t)
	found, err := localGroupContainsSID(operatorGroupName, userSID)
	if err != nil {
		t.Fatalf("SAM membership lookup failed: %v", err)
	}
	if !found {
		t.Fatalf("SAM helper did not find member %q in local group %q", userSID, operatorGroupName)
	}
}

// TestSAMOperatorMembershipAuthorisesCurrentUser proves the production fallback
// function, including the pinned group SID validation, for the current user.
func TestSAMOperatorMembershipAuthorisesCurrentUser(t *testing.T) {
	groupSID, userSID := requireCurrentOperatorMembership(t)
	member, err := samOperatorMembership(groupSID, userSID)
	if err != nil {
		t.Fatalf("SAM operator membership failed: %v", err)
	}
	if !member {
		t.Fatalf("pinned operator group %q did not report member %q", groupSID, userSID)
	}
}

// TestLocalGroupContainsNonMemberSIDs proves that a well-known SYSTEM SID and a
// syntactically valid foreign SID never authorise as operator.
func TestLocalGroupContainsNonMemberSIDs(t *testing.T) {
	requireLocalOperatorGroup(t)
	members, err := localGroupMemberSIDs(operatorGroupName)
	if err != nil {
		t.Fatalf("enumerate operator group members: %v", err)
	}
	candidates := []string{
		"S-1-5-18", // NT AUTHORITY\SYSTEM
		"S-1-5-21-1111111111-2222222222-3333333333-500",
	}
	for _, candidate := range candidates {
		if containsSID(members, candidate) {
			t.Logf("candidate %q is configured as operator member on this host, skipping", candidate)
			continue
		}
		found, lookupErr := localGroupContainsSID(operatorGroupName, candidate)
		if lookupErr != nil {
			t.Fatalf("SAM membership lookup for %q failed: %v", candidate, lookupErr)
		}
		if found {
			t.Fatalf("non-member SID %q reported as operator", candidate)
		}
	}
}

// TestLocalGroupContainsSIDRejectsInvalidInput proves that malformed group names
// and SID strings are rejected before any SAM call and never authorise.
func TestLocalGroupContainsSIDRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		group string
		sid   string
	}{
		{"empty group", "", "S-1-5-18"},
		{"nul group", "VGT GeDefense\x00Operators", "S-1-5-18"},
		{"newline group", "VGT GeDefense\nOperators", "S-1-5-18"},
		{"overlong group", strings.Repeat("G", maxLocalGroupNameBytes+1), "S-1-5-18"},
		{"empty sid", operatorGroupName, ""},
		{"nul sid", operatorGroupName, "S-1-5-18\x00"},
		{"overlong sid", operatorGroupName, "S-1-" + strings.Repeat("1-", 200)},
		{"not a sid", operatorGroupName, "administrator"},
		{"bad subauthority", operatorGroupName, "S-1-5-21-abc"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			found, err := localGroupContainsSID(test.group, test.sid)
			if err == nil {
				t.Fatalf("invalid input accepted: group=%q sid=%q", test.group, test.sid)
			}
			if found {
				t.Fatalf("invalid input authorised: group=%q sid=%q", test.group, test.sid)
			}
			if !errors.Is(err, errLocalGroupInputInvalid) {
				t.Fatalf("invalid input error classification = %v", err)
			}
		})
	}
}

// TestLocalGroupContainsSIDRejectsMissingGroup proves that a missing local group
// is an error (fail closed), not an empty membership.
func TestLocalGroupContainsSIDRejectsMissingGroup(t *testing.T) {
	found, err := localGroupContainsSID("VGT GeDefense Operators Missing Test Group", "S-1-5-18")
	if err == nil {
		t.Fatal("missing local group accepted")
	}
	if found {
		t.Fatal("missing local group authorised a member")
	}
	if !errors.Is(err, errLocalGroupNotFound) {
		t.Fatalf("missing group error classification = %v", err)
	}
}

// TestLocalGroupEnumerationBoundsAreValidated proves that invalid or oversized
// enumeration caps are rejected before an API call.
func TestLocalGroupEnumerationBoundsAreValidated(t *testing.T) {
	if err := validateLocalGroupEnumerationBounds(defaultLocalGroupEnumerationBounds()); err != nil {
		t.Fatalf("production bounds rejected: %v", err)
	}
	invalid := []struct {
		name   string
		bounds localGroupEnumerationBounds
	}{
		{"zero value", localGroupEnumerationBounds{}},
		{"no entries", localGroupEnumerationBounds{MaxEntries: 0, MaxBuffer: 256, MaxCalls: 1}},
		{"too many entries", localGroupEnumerationBounds{MaxEntries: localGroupMemberMaxEntries + 1, MaxBuffer: 1 << 20, MaxCalls: 1}},
		{"tiny buffer", localGroupEnumerationBounds{MaxEntries: 1, MaxBuffer: localGroupMemberMinBuffer - 1, MaxCalls: 1}},
		{"oversized buffer", localGroupEnumerationBounds{MaxEntries: 1, MaxBuffer: localGroupMemberMaxBuffer + 1, MaxCalls: 1}},
		{"no calls", localGroupEnumerationBounds{MaxEntries: 1, MaxBuffer: 256, MaxCalls: 0}},
		{"too many calls", localGroupEnumerationBounds{MaxEntries: 1, MaxBuffer: 256, MaxCalls: localGroupMemberMaxCalls + 1}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			err := validateLocalGroupEnumerationBounds(test.bounds)
			if err == nil {
				t.Fatalf("bounds %+v accepted", test.bounds)
			}
			if !errors.Is(err, errLocalGroupInputInvalid) {
				t.Fatalf("bounds error classification = %v", err)
			}
		})
	}
	// Input validation must also reject bad names/SIDs before the API call.
	if err := validateLocalGroupName(operatorGroupName); err != nil {
		t.Fatalf("valid operator group name rejected: %v", err)
	}
	if err := validateSIDText("S-1-5-21-1-2-3-1006"); err != nil {
		t.Fatalf("valid SID text rejected: %v", err)
	}
}

// TestLocalGroupBufferGrowthIsBounded proves the doubling growth converges on the
// hard 1 MiB cap and never loops or overshoots.
func TestLocalGroupBufferGrowthIsBounded(t *testing.T) {
	maxBuffer := uint32(localGroupMemberMaxBuffer)
	current := uint32(localGroupMemberStartBuffer)
	steps := 0
	for current < maxBuffer {
		next, ok := nextLocalGroupBufferSize(current, maxBuffer)
		if !ok {
			t.Fatalf("growth refused below the cap: current=%d", current)
		}
		if next <= current || next > maxBuffer {
			t.Fatalf("growth %d -> %d invalid for cap %d", current, next, maxBuffer)
		}
		current = next
		steps++
		if steps > 32 {
			t.Fatal("buffer growth does not converge")
		}
	}
	if current != maxBuffer {
		t.Fatalf("growth stopped at %d, want %d", current, maxBuffer)
	}
	if next, ok := nextLocalGroupBufferSize(maxBuffer, maxBuffer); ok || next != maxBuffer {
		t.Fatalf("growth beyond the cap: next=%d ok=%t", next, ok)
	}
	if next, ok := nextLocalGroupBufferSize(0, maxBuffer); ok || next != maxBuffer {
		t.Fatalf("zero growth state not capped: next=%d ok=%t", next, ok)
	}
}

// TestLocalGroupEnumerationRespectsEntryBound proves the result set never grows
// beyond the injected entry cap; with more members than the cap the enumeration
// must fail closed instead of returning a partial member list.
func TestLocalGroupEnumerationRespectsEntryBound(t *testing.T) {
	requireLocalOperatorGroup(t)
	bounds := defaultLocalGroupEnumerationBounds()
	bounds.MaxEntries = 1
	collected := make([]string, 0, 2)
	_, err := enumerateLocalGroupMembers(operatorGroupName, bounds, func(sid string) bool {
		collected = append(collected, sid)
		return false
	})
	if err != nil {
		if !errors.Is(err, errLocalGroupBoundExceeded) {
			t.Fatalf("enumeration failed with unexpected classification: %v", err)
		}
		return
	}
	if len(collected) > int(bounds.MaxEntries) {
		t.Fatalf("enumeration returned %d members beyond the cap %d", len(collected), bounds.MaxEntries)
	}
}

// TestLocalGroupEnumerationRejectsNilVisitor proves the callback contract fails
// closed instead of panicking.
func TestLocalGroupEnumerationRejectsNilVisitor(t *testing.T) {
	_, err := enumerateLocalGroupMembers(operatorGroupName, defaultLocalGroupEnumerationBounds(), nil)
	if err == nil {
		t.Fatal("nil visitor accepted")
	}
	if !errors.Is(err, errLocalGroupInputInvalid) {
		t.Fatalf("nil visitor error classification = %v", err)
	}
}

// TestOperatorGroupSAMFallbackEligibility pins when the SAM may be consulted: only
// for a group SID that is entirely absent from the token. A deny-only or disabled
// token entry is a deliberate restriction and must stay effective.
func TestOperatorGroupSAMFallbackEligibility(t *testing.T) {
	const group = "S-1-5-21-1-2-3-1006"
	tests := []struct {
		name        string
		authorising []string
		present     []string
		group       string
		want        bool
	}{
		{"unresolved group", nil, nil, "", false},
		{"token authorises", []string{group}, []string{group}, group, false},
		{"stale token absent", []string{"S-1-5-32-545"}, []string{"S-1-5-32-545"}, group, true},
		{"deny-only present", nil, []string{group}, group, false},
		{"disabled present", []string{"S-1-5-32-545"}, []string{"S-1-5-32-545", group}, group, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := operatorGroupNeedsSAMFallback(test.authorising, test.present, test.group); got != test.want {
				t.Fatalf("fallback eligibility = %t, want %t", got, test.want)
			}
		})
	}
}

// TestSAMOperatorMembershipFailsClosedOnGroupMismatch proves that a pinned group
// SID which does not resolve to the installed local group never authorises.
func TestSAMOperatorMembershipFailsClosedOnGroupMismatch(t *testing.T) {
	requireLocalOperatorGroup(t)
	userSID := currentProcessSID(t)
	wrongGroupSID := "S-1-5-21-1111111111-2222222222-3333333333-1006"
	member, err := samOperatorMembership(wrongGroupSID, userSID)
	if err == nil {
		t.Fatalf("mismatched operator group SID %q accepted", wrongGroupSID)
	}
	if member {
		t.Fatal("mismatched operator group SID authorised")
	}
	if !errors.Is(err, errOperatorGroupSIDMismatch) {
		t.Fatalf("mismatch error classification = %v", err)
	}
	if member, err := samOperatorMembership("", userSID); err == nil || member {
		t.Fatalf("empty pinned operator group SID accepted: member=%t err=%v", member, err)
	}
}

// TestSAMOperatorMembershipRejectsInvalidPeerSID proves that a malformed peer SID
// never authorises through the fallback.
func TestSAMOperatorMembershipRejectsInvalidPeerSID(t *testing.T) {
	groupSID := requireLocalOperatorGroup(t)
	for _, peerSID := range []string{"", "desktop-ggoopka\\masterboard", "S-1-5-21-\x00", strings.Repeat("9", maxSIDTextBytes+1)} {
		member, err := samOperatorMembership(groupSID, peerSID)
		if err == nil {
			t.Fatalf("invalid peer SID %q accepted", peerSID)
		}
		if member {
			t.Fatalf("invalid peer SID %q authorised", peerSID)
		}
	}
}

// TestOperatorPeerFlagsSimulatesStaleToken exercises the production decision
// chain for the reported installation bug: a token group list that does not
// carry the operator group (the state after Add-LocalGroupMember until the user
// logs off and on again) is repaired through the real SAM. The test also proves
// that the fallback never grants Administrator and that a deny-only token entry
// or a SAM failure cannot widen the result.
func TestOperatorPeerFlagsSimulatesStaleToken(t *testing.T) {
	groupSID, userSID := requireCurrentOperatorMembership(t)
	// Simulated stale token: a normal user token without the operator group.
	staleGroups := []string{"S-1-5-32-545", "S-1-5-32-114"}
	administrator, operator := operatorPeerFlags(staleGroups, staleGroups, userSID, groupSID)
	if administrator {
		t.Fatal("SAM fallback widened the Administrators path")
	}
	if !operator {
		t.Fatal("stale token without the operator group was not repaired through the SAM")
	}
	// A token that authorises keeps working even if the SAM would fail: the
	// token grant is evaluated first and never removed by the fallback.
	freshGroups := append(append([]string{}, staleGroups...), groupSID)
	if administrator, operator := operatorPeerFlags(freshGroups, freshGroups, userSID, groupSID); administrator || !operator {
		t.Fatalf("fresh token decision = admin=%t operator=%t", administrator, operator)
	}
	// Deny-only simulation: the SID is present but not authorising, so the SAM
	// must not overrule the deliberate token restriction.
	denyOnlyPresent := append(append([]string{}, staleGroups...), groupSID)
	if _, operator := operatorPeerFlags(staleGroups, denyOnlyPresent, userSID, groupSID); operator {
		t.Fatal("deny-only operator group entry was overruled by the SAM")
	}
	// SAM failure (pinned SID mismatch) must stay fail-closed for Operator while
	// the token-based Administrator flag is unaffected.
	adminGroups := []string{administratorsSID}
	administrator, operator = operatorPeerFlags(adminGroups, adminGroups, userSID,
		"S-1-5-21-1111111111-2222222222-3333333333-1006")
	if !administrator || operator {
		t.Fatalf("SAM failure decision = admin=%t operator=%t, want admin=true operator=false",
			administrator, operator)
	}
}
