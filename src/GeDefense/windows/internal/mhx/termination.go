// STATUS: PLATIN VGT SUPREME
package mhx

// TerminationTarget is a kinetic-response request that carries the process
// identity evidence observed by another engine (currently the Titan persistence
// correlation bridge). It is deliberately not a bare PID: the responder
// re-opens the live process and requires the creation time and image path to
// match before it terminates anything. That closes the PID-reuse window and
// keeps a temporal correlation from becoming kill authority over an unrelated
// process.
type TerminationTarget struct {
	// PID is the process identifier observed by the requesting engine.
	PID uint32
	// CreationUnixNano is the process creation time as it was observed. A zero
	// value is incomplete identity and must be rejected by the responder.
	CreationUnixNano int64
	// ImagePath is the kernel-reported image path observed for the PID.
	ImagePath string
	// Reason is a short, operator-readable explanation for the evidence trail.
	Reason string
}
