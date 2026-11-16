// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"testing"
	"unsafe"
)

func TestTPMStructLayoutsMatchWindowsSDKx64(t *testing.T) {
	if got := unsafe.Sizeof(tbsContextParams2{}); got != 8 {
		t.Fatalf("tbsContextParams2 size=%d, want 8", got)
	}
	if got := unsafe.Sizeof(tpmDeviceInfo{}); got != 16 {
		t.Fatalf("tpmDeviceInfo size=%d, want 16", got)
	}
}

func TestBootPostureDigestIsDeterministic(t *testing.T) {
	base := BootPosture{
		TPMAvailable:      true,
		TPMVersion:        2,
		WBCLAvailable:     true,
		WBCLBytes:         4096,
		WBCLSHA256:        "abcd",
		SecureBootKnown:   true,
		SecureBootEnabled: true,
		QuoteKind:         "tpm2-wbcl",
	}
	d1 := computeBootPostureDigest(base)
	d2 := computeBootPostureDigest(base)
	if d1 != d2 || len(d1) != 64 {
		t.Fatalf("unexpected digest pair: %q vs %q", d1, d2)
	}
	modified := base
	modified.SecureBootEnabled = false
	if d3 := computeBootPostureDigest(modified); d3 == d1 {
		t.Fatal("expected SecureBoot change to alter canonical posture digest")
	}
}

func TestMeasureBootPostureLive(t *testing.T) {
	posture, err := MeasureBootPosture()
	if err != nil {
		t.Fatalf("MeasureBootPosture returned error: %v", err)
	}
	if len(posture.Digest) != 64 {
		t.Fatalf("expected 64-char SHA256 digest, got %q", posture.Digest)
	}
	t.Logf("TPM=%v (v%d) WBCL=%v (%dB) SecureBoot=%v(%v) HVCI=%v(%v) Quote=%s Err=%q",
		posture.TPMAvailable, posture.TPMVersion,
		posture.WBCLAvailable, posture.WBCLBytes,
		posture.SecureBootEnabled, posture.SecureBootKnown,
		posture.HVCIEnabled, posture.DeviceGuardKnown,
		posture.QuoteKind, posture.LastError)
}
