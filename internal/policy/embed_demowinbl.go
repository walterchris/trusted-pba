//go:build demowinbl

package policy

import _ "embed"

//go:embed policy_demowinbl.json
var defaultJSON []byte

// Default returns the firmware-db BitLocker demo policy for `task demo:windows
// BITLOCKER=1`: require_secure_boot true and a "pba"-validated chainload of Windows
// Boot Manager. The PBA trust-brokers bootmgfw against its embedded Windows CAs AND
// firmware re-validates it against the Microsoft db on load (db = key A + MS CAs).
// Because firmware db authorizes the load, PCR 7 is a normal firmware-db boot and
// stays reproducible, so BitLocker's TPM seal auto-unlocks (unlike the Key-A-only
// pba-override model, which makes the OS-loader authority in PCR 7 non-reproducible).
// Not part of normal or release builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
