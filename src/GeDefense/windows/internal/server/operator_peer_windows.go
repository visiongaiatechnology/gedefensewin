// STATUS: PLATIN
//go:build windows

package server

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// This file implements the local OS-identity verification used by the operator
// session broker (UI-FIND-001 / AN-FIND-001 / AN-FIND-004). It inspects the
// Windows access token of the process that owns a loopback TCP connection; it
// never trusts a client-supplied account name or SID. All handles are closed and
// all buffers are bounded. If anything is unavailable the caller fails closed.

const (
	processQueryLimitedInformation = 0x1000
	tokenQueryAccess               = 0x0008

	tokenUserClass   = 1
	tokenGroupsClass = 2

	seGroupEnabled        = 0x00000004
	seGroupUseForDenyOnly = 0x00000010
	maxTokenInfoBytes     = 1 << 20

	administratorsSID = "S-1-5-32-544"
	operatorGroupName = "VGT GeDefense Operators"
	productStateKey   = `SOFTWARE\VGT\GeDefense`
	operatorGroupSID  = "OperatorGroupSid"
)

// SAM local-group enumeration bounds for the authoritative stale-token operator
// fallback. The fallback only has to answer "is this peer SID a member", so every
// resource is capped: at most 8192 members, at most 1 MiB requested per call and
// at most 8 NetLocalGroupGetMembers calls.
const (
	localGroupMemberMaxEntries  = 8192
	localGroupMemberMaxBuffer   = 1 << 20
	localGroupMemberMaxCalls    = 8
	localGroupMemberStartBuffer = 64 << 10
	localGroupMemberMinBuffer   = 256

	// localGroupMembersInfoLevel is LOCALGROUP_MEMBERS_INFO_1: the only member
	// record shape that carries the member SID.
	localGroupMembersInfoLevel = 1

	maxLocalGroupNameBytes = 256
	maxSIDTextBytes        = 256

	// NetLocalGroupGetMembers status codes. Empirically a too-small buffer
	// returns NERR_BufTooSmall (2123) without partial data, while
	// ERROR_MORE_DATA (234) signals a partial result that continues through the
	// resume handle; both are handled as retryable growth steps.
	netAPISuccess             = 0
	netAPIErrorMoreData       = 234
	netAPIErrorBufferTooSmall = 2123
	netAPIGroupNotFound       = 2220
)

var (
	operatorAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	operatorKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procOpenProcessTokenOperator      = operatorAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInformationOperator   = operatorAdvapi32.NewProc("GetTokenInformation")
	procLookupAccountSidOperator      = operatorAdvapi32.NewProc("LookupAccountSidW")
	procLookupAccountNameOperator     = operatorAdvapi32.NewProc("LookupAccountNameW")
	procConvertSidToStringSidOperator = operatorAdvapi32.NewProc("ConvertSidToStringSidW")
	procConvertStringSidToSidOperator = operatorAdvapi32.NewProc("ConvertStringSidToSidW")
	procLocalFreeOperator             = operatorKernel32.NewProc("LocalFree")

	// netapi32 bindings for the SAM membership fallback. NewLazyProc.Call
	// panics when the procedure cannot be resolved, so every call site resolves
	// the procedures with Find first and fails closed on error.
	operatorNetapi32                    = syscall.NewLazyDLL("netapi32.dll")
	procNetLocalGroupGetMembersOperator = operatorNetapi32.NewProc("NetLocalGroupGetMembers")
	procNetApiBufferFreeOperator        = operatorNetapi32.NewProc("NetApiBufferFree")

	operatorGroupSIDOnce        sync.Once
	operatorGroupSIDCached      string
	operatorGroupSIDLookupError error
)

type sidAndAttributes struct {
	Sid        uintptr
	Attributes uint32
}

// operatorPeerFromPID resolves pid to a verified Windows identity. It requires
// PROCESS_QUERY_LIMITED_INFORMATION, which a LocalSystem service holds for a
// same-machine user process without elevation of the caller.
func operatorPeerFromPID(pid uint32) (operatorPeer, error) {
	if pid == 0 {
		return operatorPeer{}, errors.New("invalid peer process id")
	}
	process, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return operatorPeer{}, fmt.Errorf("open peer process: %w", err)
	}
	defer func() { _ = syscall.CloseHandle(process) }()
	var token syscall.Token
	result, _, callErr := procOpenProcessTokenOperator.Call(
		uintptr(process), uintptr(tokenQueryAccess), uintptr(unsafe.Pointer(&token)))
	if result == 0 {
		return operatorPeer{}, fmt.Errorf("open peer process token: %w", callError(callErr))
	}
	defer func() { _ = syscall.CloseHandle(syscall.Handle(token)) }()

	userSID, account, err := tokenUserIdentity(token)
	if err != nil {
		return operatorPeer{}, err
	}
	authorisingGroups, tokenGroups, err := tokenGroupSIDs(token)
	if err != nil {
		return operatorPeer{}, err
	}
	operatorGroup := lookupOperatorGroupSID()
	administrator, operator := operatorPeerFlags(authorisingGroups, tokenGroups, userSID, operatorGroup)
	peer := operatorPeer{
		PID:           pid,
		Account:       account,
		SID:           userSID,
		Administrator: administrator,
		Operator:      operator,
	}
	return peer, nil
}

// operatorPeerFlags derives the broker authorization flags from the token group
// sets. Administrator remains token-only (the elevation path is never widened).
//
// Operator honors the SAM fallback: the installer adds the user to the local
// operator group in the SAM, but an already existing logon token keeps its group
// list until the next interactive logon. Token-only authorization therefore
// denied Center/Tray right after installation (HTTP 403). SAM is authoritative
// for the operator group, so such a stale token is repaired here; a deny-only or
// disabled token entry is not (see operatorGroupNeedsSAMFallback).
func operatorPeerFlags(authorising, present []string, userSID, operatorGroup string) (administrator, operator bool) {
	administrator = containsSID(authorising, administratorsSID)
	operator = containsSID(authorising, operatorGroup)
	if operatorGroupNeedsSAMFallback(authorising, present, operatorGroup) {
		if samMember, samErr := samOperatorMembership(operatorGroup, userSID); samErr == nil && samMember {
			operator = true
		}
	}
	return administrator, operator
}

func callError(callErr error) error {
	if callErr == nil || errors.Is(callErr, syscall.Errno(0)) {
		return errors.New("windows api call failed")
	}
	return callErr
}

func tokenUserIdentity(token syscall.Token) (string, string, error) {
	buffer, err := tokenInformation(token, tokenUserClass)
	if err != nil {
		return "", "", err
	}
	if len(buffer) < int(unsafe.Sizeof(sidAndAttributes{})) {
		return "", "", errors.New("token user buffer truncated")
	}
	user := (*sidAndAttributes)(unsafe.Pointer(&buffer[0]))
	if user.Sid == 0 {
		return "", "", errors.New("token user sid missing")
	}
	sidText, err := sidToString(user.Sid)
	if err != nil {
		return "", "", err
	}
	account, err := accountNameForSID(user.Sid)
	if err != nil {
		// A resolvable SID is sufficient for attribution; name resolution can
		// fail for deleted accounts. Keep the SID-only identity instead of
		// granting authority without an account label.
		return sidText, "", err
	}
	return sidText, account, nil
}

// tokenGroupSIDs splits the token's group list into two SID sets:
//
//   - authorising: enabled, non-deny-only groups that may grant authority,
//   - present: every group SID the token carries, including deny-only or
//     disabled entries.
//
// The second set exists so a deliberate token restriction can never be
// overruled by the SAM fallback. A SID that cannot be converted to text is
// skipped; it cannot grant or deny anything by name.
func tokenGroupSIDs(token syscall.Token) (authorising, present []string, err error) {
	buffer, err := tokenInformation(token, tokenGroupsClass)
	if err != nil {
		return nil, nil, err
	}
	if len(buffer) < 8 {
		return nil, nil, errors.New("token groups buffer truncated")
	}
	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	const groupEntrySize = int(unsafe.Sizeof(sidAndAttributes{}))
	if count > 4096 || len(buffer) < 8+int(count)*groupEntrySize {
		return nil, nil, errors.New("token groups buffer invalid")
	}
	authorising = make([]string, 0, count)
	present = make([]string, 0, count)
	for index := uint32(0); index < count; index++ {
		entry := (*sidAndAttributes)(unsafe.Pointer(&buffer[8+int(index)*groupEntrySize]))
		if entry.Sid == 0 {
			continue
		}
		sidText, sidErr := sidToString(entry.Sid)
		if sidErr != nil {
			continue
		}
		present = append(present, sidText)
		if usableTokenGroupAttribute(entry.Attributes) {
			authorising = append(authorising, sidText)
		}
	}
	return authorising, present, nil
}

// usableTokenGroupAttribute reports whether a token group entry may authorise.
// Deny-only and disabled groups never grant authority; keeping the filter in a
// helper makes the deny-only exclusion directly testable.
func usableTokenGroupAttribute(attributes uint32) bool {
	return attributes&seGroupEnabled != 0 && attributes&seGroupUseForDenyOnly == 0
}

func tokenInformation(token syscall.Token, class uint32) ([]byte, error) {
	var size uint32
	procGetTokenInformationOperator.Call(
		uintptr(token), uintptr(class), 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 || size > maxTokenInfoBytes {
		return nil, errors.New("token information size invalid")
	}
	buffer := make([]byte, size)
	var returned uint32
	result, _, callErr := procGetTokenInformationOperator.Call(
		uintptr(token), uintptr(class),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(size), uintptr(unsafe.Pointer(&returned)))
	if result == 0 {
		return nil, fmt.Errorf("get token information: %w", callError(callErr))
	}
	if returned == 0 || int(returned) > len(buffer) {
		return nil, errors.New("token information truncated")
	}
	return buffer[:returned], nil
}

func sidToString(sid uintptr) (string, error) {
	var text *uint16
	result, _, callErr := procConvertSidToStringSidOperator.Call(
		sid, uintptr(unsafe.Pointer(&text)))
	if result == 0 || text == nil {
		return "", fmt.Errorf("convert sid: %w", callError(callErr))
	}
	defer func() { _, _, _ = procLocalFreeOperator.Call(uintptr(unsafe.Pointer(text))) }()
	return utf16PtrToString(text), nil
}

// utf16PtrToString converts a NUL-terminated UTF-16 string with a hard length
// bound so a malformed Windows buffer can never cause an unbounded scan.
func utf16PtrToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	length := 0
	for length < 4096 {
		character := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(length)*2))
		if character == 0 {
			break
		}
		length++
	}
	if length == 0 {
		return ""
	}
	return syscall.UTF16ToString(unsafe.Slice(ptr, length))
}

func accountNameForSID(sid uintptr) (string, error) {
	var nameLength, domainLength uint32
	var use uint32
	procLookupAccountSidOperator.Call(0, sid, 0,
		uintptr(unsafe.Pointer(&nameLength)), 0, uintptr(unsafe.Pointer(&domainLength)),
		uintptr(unsafe.Pointer(&use)))
	if nameLength == 0 || nameLength > 1024 || domainLength > 1024 {
		return "", errors.New("account name boundary rejected")
	}
	name := make([]uint16, nameLength+1)
	domain := make([]uint16, domainLength+1)
	result, _, callErr := procLookupAccountSidOperator.Call(0, sid,
		uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLength)),
		uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&domainLength)),
		uintptr(unsafe.Pointer(&use)))
	if result == 0 {
		return "", fmt.Errorf("lookup account sid: %w", callError(callErr))
	}
	accountName := syscall.UTF16ToString(name)
	domainName := syscall.UTF16ToString(domain)
	if domainName == "" {
		return accountName, nil
	}
	return domainName + `\` + accountName, nil
}

func lookupOperatorGroupSID() string {
	operatorGroupSIDOnce.Do(func() {
		operatorGroupSIDCached, operatorGroupSIDLookupError = readOperatorGroupSIDFromRegistry()
		if operatorGroupSIDCached == "" {
			operatorGroupSIDCached, operatorGroupSIDLookupError = lookupAccountSIDByName(operatorGroupName)
		}
	})
	if operatorGroupSIDLookupError != nil {
		return ""
	}
	return operatorGroupSIDCached
}

func readOperatorGroupSIDFromRegistry() (string, error) {
	path, err := syscall.UTF16PtrFromString(productStateKey)
	if err != nil {
		return "", err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_READ, &key); err != nil {
		return "", err
	}
	defer func() { _ = syscall.RegCloseKey(key) }()
	valueName, err := syscall.UTF16PtrFromString(operatorGroupSID)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 256)
	length := uint32(len(buffer) * 2)
	var valueType uint32
	if err := syscall.RegQueryValueEx(key, valueName, nil, &valueType,
		(*byte)(unsafe.Pointer(&buffer[0])), &length); err != nil {
		return "", err
	}
	if valueType != syscall.REG_SZ {
		return "", errors.New("operator group sid value type invalid")
	}
	value := strings.TrimSpace(syscall.UTF16ToString(buffer))
	if !strings.HasPrefix(value, "S-1-5-21-") {
		return "", errors.New("operator group sid value invalid")
	}
	return value, nil
}

func lookupAccountSIDByName(name string) (string, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var sidSize, domainSize uint32
	var use uint32
	procLookupAccountNameOperator.Call(0, uintptr(unsafe.Pointer(namePtr)), 0,
		uintptr(unsafe.Pointer(&sidSize)), 0, uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&use)))
	if sidSize == 0 || sidSize > 4096 || domainSize > 1024 {
		return "", errors.New("operator group sid lookup unavailable")
	}
	sidBuffer := make([]byte, sidSize)
	domain := make([]uint16, domainSize+1)
	result, _, callErr := procLookupAccountNameOperator.Call(0,
		uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&sidBuffer[0])),
		uintptr(unsafe.Pointer(&sidSize)), uintptr(unsafe.Pointer(&domain[0])),
		uintptr(unsafe.Pointer(&domainSize)), uintptr(unsafe.Pointer(&use)))
	if result == 0 {
		return "", fmt.Errorf("lookup operator group: %w", callError(callErr))
	}
	return sidToString(uintptr(unsafe.Pointer(&sidBuffer[0])))
}

func containsSID(sids []string, wanted string) bool {
	if wanted == "" {
		return false
	}
	for _, sid := range sids {
		if sid == wanted {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Local SAM operator-group membership: authoritative stale-token fallback
// ---------------------------------------------------------------------------

// Why this exists: the installer adds the installing user to the local group
// "VGT GeDefense Operators" in the SAM. Windows logon tokens are snapshots: a
// token created before that Add-LocalGroupMember call does not contain the new
// group SID until the user signs out and in again. Token-only authorization
// therefore rejected Center/Tray directly after installation with HTTP 403,
// surfaced as "GeDefense Center konnte nicht authentifiziert geöffnet werden."
//
// Security semantics of this fallback:
//
//   - SAM is authoritative for operator-group membership: an addition becomes
//     effective for the next broker request even while the caller's token is
//     still stale, instead of only after the next logon.
//   - Membership is decided by exact SID text (sidToString) of the peer user
//     against the SIDs returned by NetLocalGroupGetMembers level 1. SAM account
//     names and every client-supplied value are never part of the decision.
//   - The group is pinned through lookupOperatorGroupSID() (installer registry
//     value, fallback LookupAccountNameW); the name used for the enumeration
//     must resolve to exactly that SID or the fallback fails closed.
//   - Direct members only: nested groups are not expanded. This is a deliberate
//     bound (no recursive group walk) and covers the installer-added member.
//   - Any failure - missing group, API error, malformed data or an exhausted
//     resource bound - yields Operator=false. Token and Administrators paths are
//     untouched, so an administrator keeps token-based authorization even when
//     the SAM is unreadable.
//   - The fallback is additive: it only widens the result for a group SID that
//     the token does not contain at all. It never narrows a token grant and it
//     never overrules a deny-only or disabled token entry.
//
// Documented residual risk: token inspection still grants whatever the logon
// snapshot carried, so a process whose token already contains the operator group
// keeps that grant until it logs off, even after the SAM removed the membership.
// Revocation therefore takes effect for new broker requests from tokens that
// never carried the group plus every new logon; it is not retroactive for an
// already running stale token.
var (
	errLocalGroupNotFound       = errors.New("local group not found")
	errLocalGroupBoundExceeded  = errors.New("local group enumeration bound exceeded")
	errLocalGroupInputInvalid   = errors.New("local group enumeration input invalid")
	errOperatorGroupSIDMismatch = errors.New("operator group sid mismatch")
)

// localGroupMembersInfo1 mirrors LOCALGROUP_MEMBERS_INFO_1. Only the SID is
// authoritative; AccountName is never dereferenced and exists purely to keep the
// native layout exact.
type localGroupMembersInfo1 struct {
	Sid         uintptr
	SidUsage    uint32
	AccountName uintptr
}

// localGroupMembersInfo1Size is the native element stride. The two blank
// constants are compile-time assertions that Go's struct layout equals the
// native layout (three pointer-sized fields: 24 bytes on 64-bit, 12 on 32-bit).
const localGroupMembersInfo1Size = unsafe.Sizeof(localGroupMembersInfo1{})

const (
	_ = uint(localGroupMembersInfo1Size - 3*unsafe.Sizeof(uintptr(0)))
	_ = uint(3*unsafe.Sizeof(uintptr(0)) - localGroupMembersInfo1Size)
)

// localGroupEnumerationBounds caps one SAM member enumeration. Production code
// uses defaultLocalGroupEnumerationBounds() only; tests inject smaller or
// invalid values to prove the caps are enforced.
type localGroupEnumerationBounds struct {
	MaxEntries uint32
	MaxBuffer  uint32
	MaxCalls   int
}

func defaultLocalGroupEnumerationBounds() localGroupEnumerationBounds {
	return localGroupEnumerationBounds{
		MaxEntries: localGroupMemberMaxEntries,
		MaxBuffer:  localGroupMemberMaxBuffer,
		MaxCalls:   localGroupMemberMaxCalls,
	}
}

func validateLocalGroupEnumerationBounds(bounds localGroupEnumerationBounds) error {
	if bounds.MaxEntries == 0 || bounds.MaxEntries > localGroupMemberMaxEntries {
		return fmt.Errorf("%w: entry bound %d", errLocalGroupInputInvalid, bounds.MaxEntries)
	}
	if bounds.MaxBuffer < localGroupMemberMinBuffer || bounds.MaxBuffer > localGroupMemberMaxBuffer {
		return fmt.Errorf("%w: buffer bound %d", errLocalGroupInputInvalid, bounds.MaxBuffer)
	}
	if bounds.MaxCalls <= 0 || bounds.MaxCalls > localGroupMemberMaxCalls {
		return fmt.Errorf("%w: call bound %d", errLocalGroupInputInvalid, bounds.MaxCalls)
	}
	return nil
}

// validateLocalGroupName rejects names that cannot address a local group before
// any API call: empty, NUL-embedded, control characters or overlong input.
func validateLocalGroupName(name string) error {
	if name == "" || len(name) > maxLocalGroupNameBytes {
		return fmt.Errorf("%w: group name length %d", errLocalGroupInputInvalid, len(name))
	}
	for index := 0; index < len(name); index++ {
		if name[index] < 0x20 || name[index] == 0x7F {
			return fmt.Errorf("%w: group name control character", errLocalGroupInputInvalid)
		}
	}
	return nil
}

// validateSIDText accepts canonical SID text ("S-1-" plus a numeric
// subauthority list). It only rejects malformed input early; membership is still
// decided by exact comparison with the SAM-returned SID text.
func validateSIDText(text string) error {
	if len(text) <= len("S-1-") || len(text) > maxSIDTextBytes || !strings.HasPrefix(text, "S-1-") {
		return fmt.Errorf("%w: sid text length %d", errLocalGroupInputInvalid, len(text))
	}
	for index := len("S-1-"); index < len(text); index++ {
		character := text[index]
		if (character < '0' || character > '9') && character != '-' {
			return fmt.Errorf("%w: sid text character", errLocalGroupInputInvalid)
		}
	}
	return nil
}

// nextLocalGroupBufferSize doubles the preferred buffer size, clamped to max, so
// a too-small buffer converges in O(log n) calls. It reports false when the
// buffer is already at the cap and cannot grow any further.
func nextLocalGroupBufferSize(current, max uint32) (uint32, bool) {
	if current == 0 || current >= max {
		return max, false
	}
	if current > max/2 {
		return max, true
	}
	return current * 2, true
}

// operatorGroupNeedsSAMFallback reports whether the SAM is the only remaining
// source for the operator group: the group SID resolved, the token does not
// authorise through it, and the token does not carry it at all. A deny-only or
// disabled token entry is a deliberate restriction and is never overruled by
// the SAM.
func operatorGroupNeedsSAMFallback(authorising, present []string, operatorGroup string) bool {
	if operatorGroup == "" {
		return false
	}
	if containsSID(authorising, operatorGroup) {
		return false
	}
	return !containsSID(present, operatorGroup)
}

// samOperatorMembership reads the operator-group membership from the SAM as the
// authoritative fallback for a stale logon token. It fails closed: the pinned
// operator group SID must equal the SID the local group name resolves to right
// now, and every membership or API error yields (false, error).
func samOperatorMembership(operatorGroup, peerSID string) (bool, error) {
	if err := validateSIDText(operatorGroup); err != nil {
		return false, fmt.Errorf("operator group sid: %w", err)
	}
	samGroupSID, err := lookupAccountSIDByName(operatorGroupName)
	if err != nil {
		return false, fmt.Errorf("resolve local operator group: %w", err)
	}
	if samGroupSID != operatorGroup {
		return false, fmt.Errorf("%w: sam=%q pinned=%q", errOperatorGroupSIDMismatch, samGroupSID, operatorGroup)
	}
	return localGroupContainsSID(operatorGroupName, peerSID)
}

// localGroupMemberSIDs returns the canonical member SIDs of the named local
// group, bounded by the production resource caps.
func localGroupMemberSIDs(groupName string) ([]string, error) {
	sids := make([]string, 0, 16)
	if _, err := enumerateLocalGroupMembers(groupName, defaultLocalGroupEnumerationBounds(), func(memberSID string) bool {
		sids = append(sids, memberSID)
		return false
	}); err != nil {
		return nil, err
	}
	return sids, nil
}

// localGroupContainsSID reports whether sidText is a direct member of the named
// local group. Only canonical SID text is compared; account names are ignored.
// The enumeration stops as soon as the SID is found.
func localGroupContainsSID(groupName, sidText string) (bool, error) {
	if err := validateSIDText(sidText); err != nil {
		return false, err
	}
	found := false
	if _, err := enumerateLocalGroupMembers(groupName, defaultLocalGroupEnumerationBounds(), func(memberSID string) bool {
		if memberSID == sidText {
			found = true
			return true
		}
		return false
	}); err != nil {
		return false, err
	}
	return found, nil
}

// enumerateLocalGroupMembers walks the direct members of a local group with
// NetLocalGroupGetMembers level 1 and invokes visit with each canonical member
// SID until visit returns true. The walk is bounded by bounds; the native buffer
// is always released with NetApiBufferFree, only entriesRead entries are
// interpreted, and every failure (including an exhausted bound) returns an
// error instead of a partial success.
func enumerateLocalGroupMembers(groupName string, bounds localGroupEnumerationBounds, visit func(string) bool) (bool, error) {
	if err := validateLocalGroupName(groupName); err != nil {
		return false, err
	}
	if err := validateLocalGroupEnumerationBounds(bounds); err != nil {
		return false, err
	}
	if visit == nil {
		return false, fmt.Errorf("%w: visitor missing", errLocalGroupInputInvalid)
	}
	// NewLazyProc.Call panics if the DLL/procedure is missing, so both are
	// resolved first and any failure fails closed.
	if err := procNetLocalGroupGetMembersOperator.Find(); err != nil {
		return false, fmt.Errorf("netapi32 local group enumeration unavailable: %w", err)
	}
	if err := procNetApiBufferFreeOperator.Find(); err != nil {
		return false, fmt.Errorf("netapi32 buffer cleanup unavailable: %w", err)
	}
	groupNamePtr, err := syscall.UTF16PtrFromString(groupName)
	if err != nil {
		return false, fmt.Errorf("encode local group name: %w", err)
	}
	preferredMax := uint32(localGroupMemberStartBuffer)
	if preferredMax > bounds.MaxBuffer {
		preferredMax = bounds.MaxBuffer
	}
	var seen uint32
	// The resume handle is a PDWORD_PTR, i.e. pointer-sized, not a DWORD.
	var resume uintptr
	for call := 0; call < bounds.MaxCalls; call++ {
		var rawBuffer *byte
		var entriesRead, totalEntries uint32
		status, _, _ := procNetLocalGroupGetMembersOperator.Call(
			0, // 0 selects the local computer as the server.
			uintptr(unsafe.Pointer(groupNamePtr)),
			uintptr(localGroupMembersInfoLevel),
			uintptr(unsafe.Pointer(&rawBuffer)),
			uintptr(preferredMax),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resume)),
		)
		// Validate the reported counts before touching the kernel buffer: the
		// API is not trusted to respect the requested bounds.
		if entriesRead > bounds.MaxEntries || seen > bounds.MaxEntries-entriesRead || totalEntries > bounds.MaxEntries {
			freeLocalGroupBuffer(rawBuffer)
			return false, fmt.Errorf("%w: entries=%d total=%d", errLocalGroupBoundExceeded, entriesRead, totalEntries)
		}
		switch status {
		case netAPISuccess, netAPIErrorMoreData:
			memberSIDs, convertErr := localGroupMemberSIDsFromBuffer(rawBuffer, entriesRead)
			freeLocalGroupBuffer(rawBuffer)
			if convertErr != nil {
				return false, convertErr
			}
			seen += entriesRead
			for _, memberSID := range memberSIDs {
				if visit(memberSID) {
					return true, nil
				}
			}
			if status == netAPISuccess {
				if totalEntries > entriesRead {
					return false, fmt.Errorf("%w: incomplete response", errLocalGroupBoundExceeded)
				}
				return false, nil
			}
			// ERROR_MORE_DATA: continue the enumeration through the resume
			// handle and grow the preferred buffer for the remaining entries.
			if next, ok := nextLocalGroupBufferSize(preferredMax, bounds.MaxBuffer); ok {
				preferredMax = next
			} else {
				return false, fmt.Errorf("%w: buffer cap", errLocalGroupBoundExceeded)
			}
		case netAPIErrorBufferTooSmall:
			freeLocalGroupBuffer(rawBuffer)
			if entriesRead != 0 {
				return false, errors.New("local group buffer too small with entries")
			}
			if next, ok := nextLocalGroupBufferSize(preferredMax, bounds.MaxBuffer); ok {
				preferredMax = next
			} else {
				return false, fmt.Errorf("%w: buffer cap", errLocalGroupBoundExceeded)
			}
		case netAPIGroupNotFound:
			freeLocalGroupBuffer(rawBuffer)
			return false, fmt.Errorf("local group %q: %w", groupName, errLocalGroupNotFound)
		default:
			freeLocalGroupBuffer(rawBuffer)
			return false, fmt.Errorf("net local group get members status %d", status)
		}
	}
	return false, fmt.Errorf("%w: call cap %d", errLocalGroupBoundExceeded, bounds.MaxCalls)
}

// localGroupMemberSIDsFromBuffer converts exactly entriesRead
// LOCALGROUP_MEMBERS_INFO_1 entries into canonical SID text. The buffer length is
// never inferred from the caller's preferred length.
func localGroupMemberSIDsFromBuffer(buffer *byte, entriesRead uint32) ([]string, error) {
	if entriesRead == 0 {
		return nil, nil
	}
	if buffer == nil {
		return nil, errors.New("local group enumeration buffer missing")
	}
	if entriesRead > localGroupMemberMaxEntries {
		return nil, fmt.Errorf("%w: entries %d", errLocalGroupBoundExceeded, entriesRead)
	}
	entries := unsafe.Slice((*localGroupMembersInfo1)(unsafe.Pointer(buffer)), int(entriesRead))
	sids := make([]string, 0, len(entries))
	for index := range entries {
		if entries[index].Sid == 0 {
			return nil, errors.New("local group member sid missing")
		}
		sidText, err := sidToString(entries[index].Sid)
		if err != nil {
			return nil, fmt.Errorf("convert local group member sid: %w", err)
		}
		sids = append(sids, sidText)
	}
	return sids, nil
}

// freeLocalGroupBuffer releases a buffer allocated by NetLocalGroupGetMembers.
// The status is deliberately ignored: the pointer is a system allocation and a
// failed free cannot grant or deny authority.
func freeLocalGroupBuffer(buffer *byte) {
	if buffer == nil {
		return
	}
	_, _, _ = procNetApiBufferFreeOperator.Call(uintptr(unsafe.Pointer(buffer)))
}
