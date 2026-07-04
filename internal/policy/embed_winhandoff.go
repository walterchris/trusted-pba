//go:build winhandoff && !pbatest && !sedtest && !policytest

package policy

import _ "embed"

//go:embed policy_winhandoff.json
var defaultJSON []byte

// Default returns a test policy with a single pba-validation entry targeting the
// staged loader (EFI/TEST/TESTAPP.EFI), embedded only in the `-tags winhandoff`
// build used by the QEMU Windows-handoff test: a real Microsoft-signed loader is
// verified by the PBA against the compiled-in trust set (built `-tags trustfull`)
// and then loaded under enforcing Secure Boot. Not part of normal builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
