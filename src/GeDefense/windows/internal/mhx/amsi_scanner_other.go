// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package mhx

import "errors"

func getAmsiScanBufferOffset() uintptr {
	return 0
}

func isAmsiPatched(pid uint32, amsiOffset uintptr) (bool, error) {
	return false, errors.New("AMSI memory scanning requires Windows")
}
