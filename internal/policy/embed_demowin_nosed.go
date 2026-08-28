//go:build demowinnosed

package policy

import _ "embed"

//go:embed policy_demowin_nosed.json
var defaultJSON []byte

// Default returns a no-SED variant of the demo:windows override policy
// (validation pba-override, sed_unlock none) used to validate the full-Windows /
// BitLocker boot through the Security2 override in isolation from the mock SED
// driver. Requires the trustbroker build tag; not part of normal or release builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
