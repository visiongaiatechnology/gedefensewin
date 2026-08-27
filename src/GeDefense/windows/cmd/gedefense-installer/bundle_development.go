// STATUS: DIAMANT VGT SUPREME
//go:build !vgt_bundle

package main

import "errors"

func installerPayload() ([]byte, error) {
	return nil, errors.New("Installer-Payload ist im Entwicklungsbuild nicht eingebettet; reproduzierbaren Release-Build verwenden")
}
