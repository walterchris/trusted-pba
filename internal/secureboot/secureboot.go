// Package secureboot reports the firmware UEFI Secure Boot state.
//
// The state-evaluation logic here is plain Go (host-testable); the actual UEFI
// variable read lives in the tamago-only build (detect_tamago.go).
package secureboot

// State is the firmware Secure Boot state, from the SecureBoot and SetupMode
// global UEFI variables.
type State struct {
	SecureBoot bool // SecureBoot == 1
	SetupMode  bool // SetupMode == 1 (platform keys not enrolled; SB not enforcing)
}

// Enforcing reports whether Secure Boot is on AND actually enforcing — per the
// UEFI spec that requires SecureBoot == 1 and SetupMode == 0. Callers MUST branch
// on this rather than on SecureBoot alone (CLAUDE.md: never treat Secure Boot
// disabled and enabled as equivalent).
func (s State) Enforcing() bool { return s.SecureBoot && !s.SetupMode }

// String renders the state for logs (carries no secrets).
func (s State) String() string {
	switch {
	case s.Enforcing():
		return "enforcing"
	case s.SecureBoot:
		return "on (setup mode)"
	default:
		return "off"
	}
}
