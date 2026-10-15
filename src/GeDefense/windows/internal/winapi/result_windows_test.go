// STATUS: PLATIN
//go:build windows

package winapi

import (
	"errors"
	"syscall"
	"testing"
)

func TestNativeResultContracts(t *testing.T) {
	if err := CheckBOOL("success", 1, syscall.ERROR_ACCESS_DENIED); err != nil {
		t.Fatalf("stale last error became a failure: %v", err)
	}
	if err := CheckBOOL("failure", 0, syscall.ERROR_ACCESS_DENIED); !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		t.Fatalf("lost native error: %v", err)
	}
	if err := CheckBOOL("missing last error", 0, syscall.Errno(0)); err == nil {
		t.Fatal("zero result accepted")
	}
	if CheckHRESULT("S_OK", 0) != nil || CheckHRESULT("S_FALSE", 1) != nil {
		t.Fatal("successful HRESULT rejected")
	}
	if CheckHRESULT("E_FAIL", 0x80004005) == nil {
		t.Fatal("failed HRESULT accepted")
	}
}
