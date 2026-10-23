// STATUS: DIAMANT VGT SUPREME
//go:build windows

package geoip

import (
	"errors"
	"io"
	"os"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// openGeoIPRegularFile opens the dataset through the Win32 FILE_FLAG_OPEN_REPARSE_POINT
// primitive and rejects directories, reparse points (symlinks, junctions,
// mount points, cloud placeholder tags) and non-regular objects. The returned
// handle is the only view of the dataset used for hashing and parsing
// (DP-FIND-007: no check-then-reopen window).
func openGeoIPRegularFile(path string) (*os.File, error) {
	file, metadata, err := winapi.OpenRegularFileNoReparse(path)
	if err != nil {
		return nil, err
	}
	if metadata.Size <= 0 || metadata.Size > maxGeoIPCSVBytes {
		_ = file.Close()
		return nil, errors.New("geoip database size outside limit")
	}
	return file, nil
}

func readGeoIPSidecar(sidecar string) ([]byte, error) {
	file, _, err := winapi.OpenRegularFileNoReparse(sidecar)
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
