//go:build demolinuxplain

package policy

import _ "embed"

//go:embed policy_demolinuxplain.json
var defaultJSON []byte

// Default returns the demo policy for `task demo:linux SECUREBOOT=0`: no Secure
// Boot, mock SED unlock (console credential), then a pba-validated chainload of the
// Key-B signed Alpine UKI (the PBA verifies it against the broker trust store; with
// Secure Boot off there is no firmware gate). Embedded only in the
// -tags demolinuxplain,pbatest build the demo launcher boots.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
