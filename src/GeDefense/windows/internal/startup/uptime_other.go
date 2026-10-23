//go:build !windows

package startup

import "time"

var processStarted = time.Now()

func readUptime() uint64 {
	return uint64(time.Since(processStarted).Milliseconds())
}
