// STATUS: DIAMANT VGT SUPREME
//go:build windows

package titan

import "context"

// startPlatformSensors wires the native Windows collectors. Each collector is
// independently supervised by the engine; a failing collector cannot silently
// turn into a healthy sensor.
func (e *Engine) startPlatformSensors(ctx context.Context) error {
	e.runPersistenceLoop(ctx)
	e.runProcessSensor(ctx)
	e.runFileSensors(ctx)
	return nil
}
