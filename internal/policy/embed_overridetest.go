//go:build overridetest && !sedtest

package policy

import _ "embed"

//go:embed policy_overridetest.json
var defaultJSON []byte

// Default returns a test policy with a single pba-override entry, embedded only in
// the `-tags overridetest` build used by the QEMU trust-broker override matrix
// (built with `-tags overridetest,pbatest,trustbroker`: the pbatest test-CA trust
// store validates a fixture signed by a CA that is NOT in the firmware db, and the
// override lets it load under enforcing Secure Boot). Not part of normal builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
