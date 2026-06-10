//go:build sedtest

package policy

import _ "embed"

//go:embed policy_sed.json
var defaultJSON []byte

// Default returns a test policy with sed_unlock "required" and the shared-spec
// Admin1 test PIN (test/fixtures/opal/), embedded only in the `-tags sedtest`
// build used by the QEMU mock-Opal unlock→MBRDone→chainload matrix. on_error is
// "halt" so failed runs end deterministically for the serial harness. Not part
// of normal builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
