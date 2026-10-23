// STATUS: DIAMANT VGT SUPREME
//go:build windows

package titan

import "github.com/visiongaiatechnology/gedefense/windows/internal/winapi"

func replaceFile(temporaryPath, path string) error {
	return winapi.MoveFileReplace(temporaryPath, path)
}

func replaceNoOverwrite(fromPath, toPath string) error {
	return winapi.MoveFileNoReplace(fromPath, toPath)
}
