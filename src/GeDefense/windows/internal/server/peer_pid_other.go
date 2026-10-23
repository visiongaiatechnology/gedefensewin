// STATUS: PLATIN
//go:build !windows

package server

import "errors"

// The peer-process binding used for the credential-free browser bootstrap is a
// Windows-only control. On other platforms the exchange fails closed; the
// legacy master-authorised bootstrap code path remains available for tests.
func lookupPeerProcessID(string) (uint32, error) {
	return 0, errors.New("peer process lookup is only available on Windows")
}

func lookupPeerProcessIDForPort(string, uint16) (uint32, error) {
	return 0, errors.New("peer process lookup is only available on Windows")
}

func processDescendsFrom(uint32, uint32) bool { return false }
