// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

// Exact x64 Windows SDK (10.0.26100.0) TBS & Platform Crypto Provider constants
// and structures verified via MSVC cl.exe.

const (
	tbsSuccess         uint32 = 0x00000000
	tbsETPMNotFound    uint32 = 0x8028400F
	tbsContextVersion2 uint32 = 2
	tbsIncludeTPM12    uint32 = 1 << 1
	tbsIncludeTPM20    uint32 = 1 << 2
	tbsTCGLogSRTM      uint32 = 0

	ncryptPCPProviderName   = "Microsoft Platform Crypto Provider"
	ncryptPCPPCRTableProp   = "PCP_PCRTABLE"
	ncryptPCPTPMVersionProp = "PCP_TPM_VERSION"

	maxWBCLBytes = 1 << 20 // 1 MiB hard upper bound on measured boot log
)

// tbsContextParams2 mirrors TBS_CONTEXT_PARAMS2 (8 bytes).
type tbsContextParams2 struct {
	Version uint32
	Flags   uint32
}

// tpmDeviceInfo mirrors TPM_DEVICE_INFO (16 bytes).
type tpmDeviceInfo struct {
	StructVersion    uint32
	TPMVersion       uint32
	TPMInterfaceType uint32
	TPMImpRevision   uint32
}

// BootPosture captures measured TPM, TCG WBCL, Secure Boot and VBS/HVCI facts.
// Absent or denied hardware signals remain zero/false with QuoteKind="none".
type BootPosture struct {
	TPMAvailable      bool   `json:"tpmAvailable"`
	TPMVersion        uint32 `json:"tpmVersion"`
	TPMInterfaceType  uint32 `json:"tpmInterfaceType"`
	TPMRevision       uint32 `json:"tpmRevision"`
	WBCLAvailable     bool   `json:"wbclAvailable"`
	WBCLBytes         int    `json:"wbclBytes"`
	WBCLSHA256        string `json:"wbclSha256,omitempty"`
	PCRCount          int    `json:"pcrCount"`
	PCRTableSHA256    string `json:"pcrTableSha256,omitempty"`
	SecureBootKnown   bool   `json:"secureBootKnown"`
	SecureBootEnabled bool   `json:"secureBootEnabled"`
	DeviceGuardKnown  bool   `json:"deviceGuardKnown"`
	VBSConfigured     bool   `json:"vbsConfigured"`
	HVCIEnabled       bool   `json:"hvciEnabled"`
	QuoteKind         string `json:"quoteKind"`
	Digest            string `json:"digest"`
	LastError         string `json:"lastError,omitempty"`
}
