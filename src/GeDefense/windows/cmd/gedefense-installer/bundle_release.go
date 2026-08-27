// STATUS: DIAMANT VGT SUPREME
//go:build vgt_bundle

package main

import (
	_ "embed"
	"errors"
)

//go:embed bundle/payload.zip
var embeddedInstallerPayload []byte

func installerPayload() ([]byte, error) {
	if len(embeddedInstallerPayload) == 0 {
		return nil, errors.New("eingebettetes Installer-Payload ist leer")
	}
	return embeddedInstallerPayload, nil
}
