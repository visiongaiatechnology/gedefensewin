//go:build windows

package startup

import "syscall"

var getTickCount64 = syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64")

func readUptime() uint64 {
	value, _, _ := getTickCount64.Call()
	return uint64(value)
}
