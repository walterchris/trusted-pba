//go:build !policytest && !pbatest && !sedtest && !winhandoff && !consoletest && !keyfiletest

package policy

import _ "embed"

//go:embed policy.json
var defaultJSON []byte

// Default returns the compiled-in default policy (embedded policy.json).
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
