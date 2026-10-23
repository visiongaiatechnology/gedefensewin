// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package geoip

import (
	"errors"
	"io"
	"os"
)

// openGeoIPRegularFile is the portable fallback: open once, then reject
// symlinks/reparse-like objects based on the opened descriptor.
func openGeoIPRegularFile(path string) (*os.File, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !linkInfo.Mode().IsRegular() || linkInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("geoip database must be a regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxGeoIPCSVBytes {
		_ = file.Close()
		return nil, errors.New("geoip database size outside limit")
	}
	return file, nil
}

func readGeoIPSidecar(sidecar string) ([]byte, error) {
	linkInfo, err := os.Lstat(sidecar)
	if err != nil {
		return nil, err
	}
	if !linkInfo.Mode().IsRegular() || linkInfo.Mode()&os.ModeSymlink != 0 || linkInfo.Size() <= 0 || linkInfo.Size() > 512 {
		return nil, errors.New("geoip checksum must be a small regular file, not a symlink")
	}
	file, err := os.Open(sidecar)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	payload, err := io.ReadAll(io.LimitReader(file, 513))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > 512 {
		return nil, errors.New("geoip checksum size rejected")
	}
	return payload, nil
}
