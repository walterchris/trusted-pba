//go:build pbatest

package policy

import _ "embed"

//go:embed policy_pba.json
var defaultJSON []byte

// Default returns a test policy whose single entry uses validation "pba", embedded
// only in the `-tags pbatest` build used by the QEMU pba verify-then-load matrix.
// Not part of normal builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
