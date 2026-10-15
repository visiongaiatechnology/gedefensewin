//go:build !windows

package traffic

func ReadInterfaces() (map[uint32]Counters, error) { return nil, ErrUnavailable }
