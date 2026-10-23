// STATUS: PLATIN
//go:build !windows

package server

import "errors"

// operatorPeerFromPID is only implemented for the Windows product. The server
// package builds on non-Windows hosts for tooling and tests; the broker fails
// closed there.
func operatorPeerFromPID(uint32) (operatorPeer, error) {
	return operatorPeer{}, errors.New("operator peer verification is only available on Windows")
}
