//go:build consoletest

package policy

import _ "embed"

//go:embed policy_console.json
var defaultJSON []byte

// Default returns a test policy with sed_unlock "required" and the interactive
// `console` credential source (no compiled-in PIN), embedded only in the
// `-tags consoletest` build used to manually exercise the console passphrase
// prompt in QEMU. on_error is "halt" so a failed/aborted entry ends
// deterministically. Not part of normal builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
