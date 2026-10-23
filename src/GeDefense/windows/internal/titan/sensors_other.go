// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package titan

import (
	"context"
	"errors"
)

func (e *Engine) startPlatformSensors(context.Context) error {
	return errors.New("Titan native sensors are not available on this platform")
}
