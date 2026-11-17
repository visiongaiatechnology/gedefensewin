// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	fwpuclnt = syscall.NewLazyDLL("fwpuclnt.dll")

	procFwpmEngineOpen0          = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0         = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0    = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0   = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0    = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmSubLayerAdd0         = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerGetByKey0    = fwpuclnt.NewProc("FwpmSubLayerGetByKey0")
	procFwpmFilterAdd0           = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0    = fwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmFilterGetById0       = fwpuclnt.NewProc("FwpmFilterGetById0")
	procFwpmGetAppIdFromFileName = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0          = fwpuclnt.NewProc("FwpmFreeMemory0")
)

// WFPEngine manages dynamic WFP filters inside the GeDefense sublayer.
type WFPEngine struct {
	mu           sync.Mutex
	handle       uintptr
	dryRun       bool
	installedIDs []uint64
	lastError    string
	plannedCount int
}

// NewWFPEngine creates a WFP manager. No kernel engine handle is opened until SyncPolicy.
func NewWFPEngine() *WFPEngine {
	return &WFPEngine{}
}

// Status reports the honest WFP state without mutating anything.
func (e *WFPEngine) Status() WFPStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return WFPStatus{
		DryRun:       e.dryRun,
		Active:       e.handle != 0 && len(e.installedIDs) > 0,
		FilterIDs:    append([]uint64(nil), e.installedIDs...),
		PlannedRules: e.plannedCount,
		LastError:    e.lastError,
	}
}

// BuildWFPPlan converts a high-level WFPConfig into validated, bounded filter specs.
func BuildWFPPlan(cfg WFPConfig) ([]WFPRuleSpec, error) {
	var rules []WFPRuleSpec

	if cfg.BlockMetadata {
		metaV4 := []string{"169.254.0.0/16", "100.100.100.200/32"}
		for _, cidr := range metaV4 {
			rules = append(rules, WFPRuleSpec{
				Name:      "GeDefense-V6-Veto-" + cidr,
				LayerGUID: FWPMLayerALEAuthConnectV4,
				Action:    fwpActionBlock,
				Weight:    15,
				Prefix:    netip.MustParsePrefix(cidr),
			})
		}
		metaV6 := []string{"fe80::/10", "fd00:ec2::254/128"}
		for _, cidr := range metaV6 {
			rules = append(rules, WFPRuleSpec{
				Name:      "GeDefense-V6-Veto-" + cidr,
				LayerGUID: FWPMLayerALEAuthConnectV6,
				Action:    fwpActionBlock,
				Weight:    15,
				Prefix:    netip.MustParsePrefix(cidr),
			})
		}
	}

	if cfg.PinDNSToResolvers {
		for _, addr := range cfg.AllowedDNSServers {
			addr = addr.Unmap()
			if !addr.IsValid() || addr.IsUnspecified() {
				return nil, fmt.Errorf("winapi wfp: invalid DNS server %v", addr)
			}
			layer := FWPMLayerALEAuthConnectV4
			bits := 32
			if addr.Is6() {
				layer = FWPMLayerALEAuthConnectV6
				bits = 128
			}
			prefix := netip.PrefixFrom(addr, bits)
			for _, port := range []uint16{53, 853} {
				rules = append(rules, WFPRuleSpec{
					Name:      fmt.Sprintf("GeDefense-V6-PermitDNS-%s-%d", addr, port),
					LayerGUID: layer,
					Action:    fwpActionPermit,
					Weight:    14,
					Prefix:    prefix,
					Port:      port,
				})
			}
		}
		for _, layer := range []syscall.GUID{FWPMLayerALEAuthConnectV4, FWPMLayerALEAuthConnectV6} {
			for _, port := range []uint16{53, 853} {
				rules = append(rules, WFPRuleSpec{
					Name:      fmt.Sprintf("GeDefense-V6-BlockUnpinnedDNS-%d", port),
					LayerGUID: layer,
					Action:    fwpActionBlock,
					Weight:    8,
					Port:      port,
				})
			}
		}
	}

	for _, rawPath := range cfg.PermitAppPaths {
		cleaned := strings.TrimSpace(rawPath)
		if cleaned == "" || !filepath.IsAbs(cleaned) || len(cleaned) > 512 {
			return nil, fmt.Errorf("winapi wfp: permit app path %q must be bounded & absolute", rawPath)
		}
		for _, layer := range []syscall.GUID{FWPMLayerALEAuthConnectV4, FWPMLayerALEAuthConnectV6} {
			rules = append(rules, WFPRuleSpec{
				Name:      "GeDefense-V6-PermitApp-" + filepath.Base(cleaned),
				LayerGUID: layer,
				Action:    fwpActionPermit,
				Weight:    13,
				AppPath:   cleaned,
			})
		}
	}

	for _, rawPath := range cfg.BlockAppPaths {
		cleaned := strings.TrimSpace(rawPath)
		if cleaned == "" || !filepath.IsAbs(cleaned) || len(cleaned) > 512 {
			return nil, fmt.Errorf("winapi wfp: blocked app path %q must be bounded & absolute", rawPath)
		}
		for _, layer := range []syscall.GUID{FWPMLayerALEAuthConnectV4, FWPMLayerALEAuthConnectV6} {
			rules = append(rules, WFPRuleSpec{
				Name:      "GeDefense-V6-BlockApp-" + filepath.Base(cleaned),
				LayerGUID: layer,
				Action:    fwpActionBlock,
				Weight:    12,
				AppPath:   cleaned,
			})
		}
	}

	for _, p := range cfg.ExtraBlockPrefixes {
		if !p.IsValid() {
			return nil, errors.New("winapi wfp: invalid extra block prefix")
		}
		layer := FWPMLayerALEAuthConnectV4
		if p.Addr().Is6() {
			layer = FWPMLayerALEAuthConnectV6
		}
		rules = append(rules, WFPRuleSpec{
			Name:      "GeDefense-V6-BlockPrefix-" + p.String(),
			LayerGUID: layer,
			Action:    fwpActionBlock,
			Weight:    10,
			Prefix:    p,
		})
	}

	if len(rules) > maxWFPFilters {
		return nil, fmt.Errorf("winapi wfp: planned rule count %d exceeds %d", len(rules), maxWFPFilters)
	}
	return rules, nil
}

// SyncPolicy compiles cfg and either validates it (DryRun) or installs it
// atomically via FwpmTransactionBegin0/Commit0 with filter read-back verification.
func (e *WFPEngine) SyncPolicy(ctx context.Context, cfg WFPConfig) (WFPStatus, error) {
	if ctx != nil && ctx.Err() != nil {
		return WFPStatus{}, ctx.Err()
	}
	rules, err := BuildWFPPlan(cfg)
	if err != nil {
		return WFPStatus{}, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.dryRun = cfg.DryRun
	e.plannedCount = len(rules)

	if cfg.DryRun {
		e.lastError = ""
		return WFPStatus{
			DryRun:       true,
			Active:       false,
			PlannedRules: len(rules),
		}, nil
	}

	if err := e.ensureOpenLocked(); err != nil {
		e.lastError = err.Error()
		return WFPStatus{PlannedRules: len(rules), LastError: e.lastError}, err
	}

	if r1, _, _ := procFwpmTransactionBegin0.Call(e.handle, 0); r1 != 0 {
		err := wfpStatusError("FwpmTransactionBegin0", r1)
		e.lastError = err.Error()
		return WFPStatus{PlannedRules: len(rules), LastError: e.lastError}, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _, _ = procFwpmTransactionAbort0.Call(e.handle)
		}
	}()

	if err := e.ensureSublayerLocked(); err != nil {
		e.lastError = err.Error()
		return WFPStatus{PlannedRules: len(rules), LastError: e.lastError}, err
	}

	for _, oldID := range e.installedIDs {
		_, _, _ = procFwpmFilterDeleteById0.Call(e.handle, uintptr(oldID))
	}

	newIDs := make([]uint64, 0, len(rules))
	for idx, rule := range rules {
		if ctx != nil && ctx.Err() != nil {
			return WFPStatus{}, ctx.Err()
		}
		id, addErr := e.addAndVerifyRuleLocked(rule, uint32(idx+1))
		if addErr != nil {
			e.lastError = addErr.Error()
			return WFPStatus{PlannedRules: len(rules), LastError: e.lastError}, addErr
		}
		newIDs = append(newIDs, id)
	}

	if r1, _, _ := procFwpmTransactionCommit0.Call(e.handle); r1 != 0 {
		err := wfpStatusError("FwpmTransactionCommit0", r1)
		e.lastError = err.Error()
		return WFPStatus{PlannedRules: len(rules), LastError: e.lastError}, err
	}
	committed = true
	e.installedIDs = newIDs
	e.lastError = ""
	return WFPStatus{
		DryRun:       false,
		Active:       len(newIDs) > 0,
		FilterIDs:    append([]uint64(nil), newIDs...),
		PlannedRules: len(rules),
	}, nil
}

// Close removes dynamic filters and closes the WFP engine handle idempotently.
func (e *WFPEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle == 0 {
		return nil
	}
	for _, id := range e.installedIDs {
		_, _, _ = procFwpmFilterDeleteById0.Call(e.handle, uintptr(id))
	}
	e.installedIDs = nil
	r1, _, _ := procFwpmEngineClose0.Call(e.handle)
	e.handle = 0
	if r1 != 0 {
		return wfpStatusError("FwpmEngineClose0", r1)
	}
	return nil
}

func (e *WFPEngine) ensureOpenLocked() error {
	if e.handle != 0 {
		return nil
	}
	namePtr, _ := utf16Ptr("GeDefense-V6-Sovereign-WFP")
	descPtr, _ := utf16Ptr("GeDefense V6 Dynamic Anti-Spyware Egress Filters")
	session := fwpmSession0{
		DisplayData: fwpmDisplayData0{Name: namePtr, Description: descPtr},
		Flags:       fwpmSessionFlagDynamic,
	}
	var engineHandle uintptr
	r1, _, _ := procFwpmEngineOpen0.Call(
		0,
		uintptr(rpcCAuthnDefault),
		0,
		uintptr(unsafe.Pointer(&session)),
		uintptr(unsafe.Pointer(&engineHandle)),
	)
	runtime.KeepAlive(session)
	runtime.KeepAlive(namePtr)
	runtime.KeepAlive(descPtr)
	if r1 != 0 {
		return wfpStatusError("FwpmEngineOpen0", r1)
	}
	e.handle = engineHandle
	return nil
}

func (e *WFPEngine) ensureSublayerLocked() error {
	var existing uintptr
	rGet, _, _ := procFwpmSubLayerGetByKey0.Call(e.handle, uintptr(unsafe.Pointer(&guidGeDefenseWFPSublayer)), uintptr(unsafe.Pointer(&existing)))
	if rGet == 0 {
		if existing != 0 {
			_, _, _ = procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&existing)))
		}
		return nil
	}
	namePtr, _ := utf16Ptr("GeDefense V6 Sovereign Sublayer")
	descPtr, _ := utf16Ptr("Dynamic egress metadata and DNS enforcement sublayer")
	sublayer := fwpmSublayer0{
		SubLayerKey: guidGeDefenseWFPSublayer,
		DisplayData: fwpmDisplayData0{Name: namePtr, Description: descPtr},
		Weight:      0x7FFF,
	}
	rAdd, _, _ := procFwpmSubLayerAdd0.Call(e.handle, uintptr(unsafe.Pointer(&sublayer)), 0)
	runtime.KeepAlive(sublayer)
	runtime.KeepAlive(namePtr)
	runtime.KeepAlive(descPtr)
	if rAdd != 0 {
		return wfpStatusError("FwpmSubLayerAdd0", rAdd)
	}
	return nil
}

func (e *WFPEngine) addAndVerifyRuleLocked(rule WFPRuleSpec, seed uint32) (uint64, error) {
	namePtr, err := utf16Ptr(rule.Name)
	if err != nil {
		return 0, err
	}
	var conds []fwpmFilterCondition0
	var keepalive []any

	if rule.Prefix.IsValid() {
		addr := rule.Prefix.Addr().Unmap()
		if addr.Is4() {
			b4 := addr.As4()
			ipHost := binary.BigEndian.Uint32(b4[:])
			bits := rule.Prefix.Bits()
			var maskHost uint32
			if bits > 0 {
				maskHost = ^uint32(0) << (32 - bits)
			}
			v4 := fwpV4AddrAndMask{Addr: ipHost, Mask: maskHost}
			keepalive = append(keepalive, &v4)
			conds = append(conds, fwpmFilterCondition0{
				FieldKey:       FWPMConditionIPRemoteAddress,
				MatchType:      fwpMatchEqual,
				ConditionValue: fwpConditionValue0{Type: fwpV4AddrMask, Value: uint64(uintptr(unsafe.Pointer(&v4)))},
			})
		} else {
			v6 := fwpV6AddrAndMask{Addr: addr.As16(), PrefixLength: uint8(rule.Prefix.Bits())}
			keepalive = append(keepalive, &v6)
			conds = append(conds, fwpmFilterCondition0{
				FieldKey:       FWPMConditionIPRemoteAddress,
				MatchType:      fwpMatchEqual,
				ConditionValue: fwpConditionValue0{Type: fwpV6AddrMask, Value: uint64(uintptr(unsafe.Pointer(&v6)))},
			})
		}
	}

	if rule.Port != 0 {
		conds = append(conds, fwpmFilterCondition0{
			FieldKey:       FWPMConditionIPRemotePort,
			MatchType:      fwpMatchEqual,
			ConditionValue: fwpConditionValue0{Type: fwpUInt16, Value: uint64(rule.Port)},
		})
	}

	if rule.Protocol != 0 {
		conds = append(conds, fwpmFilterCondition0{
			FieldKey:       FWPMConditionIPProtocol,
			MatchType:      fwpMatchEqual,
			ConditionValue: fwpConditionValue0{Type: fwpUInt8, Value: uint64(rule.Protocol)},
		})
	}

	var appBlobPtr uintptr
	if rule.AppPath != "" {
		appPtr, err := utf16Ptr(rule.AppPath)
		if err != nil {
			return 0, err
		}
		rApp, _, _ := procFwpmGetAppIdFromFileName.Call(uintptr(unsafe.Pointer(appPtr)), uintptr(unsafe.Pointer(&appBlobPtr)))
		runtime.KeepAlive(appPtr)
		if rApp != 0 {
			return 0, wfpStatusError("FwpmGetAppIdFromFileName0", rApp)
		}
		defer func() {
			if appBlobPtr != 0 {
				_, _, _ = procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&appBlobPtr)))
			}
		}()
		conds = append(conds, fwpmFilterCondition0{
			FieldKey:       FWPMConditionALEAppID,
			MatchType:      fwpMatchEqual,
			ConditionValue: fwpConditionValue0{Type: fwpByteBlobType, Value: uint64(appBlobPtr)},
		})
	}

	filterKey := syscall.GUID{
		Data1: 0x9b2f7c15,
		Data2: uint16(seed),
		Data3: 0x4d89,
		Data4: [8]byte{0x91, 0x0b, 0x56, 0x47, 0x45, 0x36, 0x10, byte(seed)},
	}
	filter := fwpmFilter0{
		FilterKey:   filterKey,
		DisplayData: fwpmDisplayData0{Name: namePtr},
		LayerKey:    rule.LayerGUID,
		SubLayerKey: guidGeDefenseWFPSublayer,
		Weight:      fwpValue0{Type: fwpUInt8, Value: uint64(rule.Weight)},
		Action:      fwpmAction0{Type: rule.Action},
	}
	if len(conds) > 0 {
		filter.NumFilterConditions = uint32(len(conds))
		filter.FilterCondition = &conds[0]
	}

	var id uint64
	rAdd, _, _ := procFwpmFilterAdd0.Call(e.handle, uintptr(unsafe.Pointer(&filter)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(filter)
	runtime.KeepAlive(conds)
	runtime.KeepAlive(keepalive)
	runtime.KeepAlive(namePtr)
	if rAdd != 0 {
		return 0, wfpStatusError("FwpmFilterAdd0", rAdd)
	}

	var readback uintptr
	rGet, _, _ := procFwpmFilterGetById0.Call(e.handle, uintptr(id), uintptr(unsafe.Pointer(&readback)))
	if rGet != 0 {
		return 0, wfpStatusError("FwpmFilterGetById0", rGet)
	}
	if readback != 0 {
		_, _, _ = procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&readback)))
	}
	return id, nil
}

func wfpStatusError(op string, code uintptr) error {
	return fmt.Errorf("winapi wfp %s failed (0x%08x): %w", op, uint32(code), syscall.Errno(code))
}
