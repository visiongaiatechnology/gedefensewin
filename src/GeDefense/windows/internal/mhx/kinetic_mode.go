// STATUS: DIAMANT VGT SUPREME
package mhx

// Kinetic arming model (Windows Beta V5)
//
// Kinetic remains an observe-only intake classifier. Arming it authorizes
// burst + Threat-IP correlation only; it never installs WFP rules and never
// authorizes a process termination. The actual firewall enforcement belongs to
// the existing verified WFP threat-intelligence generation.
//
// The implementation lives in kinetic_state.go:
//   - the observation policy and the operator arming intent are atomically
//     persisted to %ProgramData%\VGT\GeDefense\mhx\kinetic-settings.json;
//   - a restart reloads the policy and the desired armed intent, but always
//     starts effectively disarmed (fail-secure);
//   - the persisted intent is promoted only after the existing verified
//     Threat-IP/WFP generation checks pass again (kinetic.ArmingRequirements);
//   - sustained loss of those requirements drops effective arming while the
//     persisted intent stays pending for automatic re-arm;
//   - a failed persistence write never reports arming and never leaves a
//     misleading persisted armed state.
