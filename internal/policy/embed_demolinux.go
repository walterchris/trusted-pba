//go:build demolinux

package policy

import _ "embed"

//go:embed policy_demolinux.json
var defaultJSON []byte

// Default returns the demo policy for `task demo:linux`: sed_unlock "required"
// with the shared-spec Admin1 test PIN (matching the MockOpalDxe mock SED), and a
// firmware-validated chainload of the Alpine UKI staged at EFI/LINUX/ALPINE.EFI.
// Embedded only in the `-tags demolinux` build the demo launcher boots; on_error
// is "halt" so a failed unlock stops deterministically. Not part of normal or
// release builds (policy-pin is release-gated — CheckReleaseReady rejects it).
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
