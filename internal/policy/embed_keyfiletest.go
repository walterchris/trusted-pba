//go:build keyfiletest

package policy

import _ "embed"

//go:embed policy_keyfile.json
var defaultJSON []byte

// Default returns a test policy with sed_unlock "required" and the `keyfile`
// credential source (path EFI/KEY/sed.key, no compiled-in PIN), embedded only in
// the `-tags keyfiletest` build used by the QEMU mock-Opal keyfile matrix. The
// harness stages the key on the ESP at that path before boot. on_error is "halt"
// so a failed/aborted run ends deterministically for the serial harness. Not part
// of normal builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
