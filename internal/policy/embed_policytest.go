//go:build policytest && !pbatest

package policy

import _ "embed"

//go:embed policy_require_sb.json
var defaultJSON []byte

// Default returns a test policy with require_secure_boot=true, embedded only in
// the `-tags policytest` build used by the Secure-Boot-required fail-closed QEMU
// test. Not part of normal builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
