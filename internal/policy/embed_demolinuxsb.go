//go:build demolinuxsb

package policy

import _ "embed"

//go:embed policy_demolinuxsb.json
var defaultJSON []byte

// Default returns the demo policy for `task demo:linux` with Secure Boot enforcing:
// mock SED unlock (console credential) then a pba-override chainload of the Key-B
// signed Alpine UKI. Firmware db carries only the PBA's key; the Security2 override
// admits the broker-trusted UKI (validation "pba-override"). Embedded only in the
// -tags demolinuxsb,pbatest,trustbroker build the demo launcher boots.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
