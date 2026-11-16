// STATUS: PLATIN VGT SUPREME

// Package lockdown is the Windows Emergency Lockdown engine (V6 phase 1).
//
// It is the 1:1 semantic port of the Linux control-plane lockdown engine
// (control/lockdown*.go) and of the Rust core policies (lockdown_usb.rs,
// lockdown_brokers.rs) onto Windows. The package is pure Go and depends only on
// the standard library.
//
// # Architecture
//
//   - settings.go owns the validated, immutable Settings. Every out-of-bounds
//     value is rejected instead of silently clamped; DefaultSettings is the only
//     source of defaults and it is inert (Enabled=false).
//   - state.go owns the crash-safe, AES-256-GCM sealed latch document
//     (lockdown-engine.state). A document that does not authenticate or does not
//     validate latches the engine fail-closed; it never releases it.
//   - phases.go owns the Phase abstraction and its error-isolating orchestration.
//     A phase that fails never prevents the remaining phases from running and a
//     failed phase is never reported as "locked".
//   - usb_policy.go is the pure composite-BadUSB classifier (USB class codes).
//   - brokers.go is the PID+creation-time-bound, reversible broker freezer. Its
//     honest status is frozen-not-locked: a reversible freeze, not a zeroized
//     key store.
//   - triggers.go is the pure trigger/dedupe/cooldown/priority correlation.
//   - engine.go/clear.go own the lifecycle, the latch transitions, the explicit
//     cancellation and the snapshottable Status.
//   - windows_actions.go and windows_device_windows.go contain the thin but real
//     Windows adapters (ntdll suspend/resume, WTS/lock workstation, CfgMgr32
//     device disable/enable). Actions that cannot be implemented safely without
//     administrator privileges return the documented NOT_IMPLEMENTED error
//     instead of faking success.
//
// # Deliberate deviations from the Linux engine
//
// The Windows engine keeps the latch when a release step fails
// (ErrReleaseIncomplete) so the operator can retry the clear without leaving a
// suspended broker process behind. The Linux engine releases the latch and only
// reports the failed reversal. The Windows behaviour is the fail-closed
// direction and is covered by tests.
package lockdown
