//go:build demosb

package policy

import _ "embed"

//go:embed policy_demosb.json
var defaultJSON []byte

// Default returns the demo policy for `task demo:secureboot`: require_secure_boot
// true, and a "pba" (trust-broker) validation of the Alpine UKI staged at
// EFI/LINUX/ALPINE.EFI — the PBA verifies the image's Authenticode against its
// embedded trust store before loading. Built `-tags pbatest,demosb`, so the trust
// store is the demo broker CA (truststore/embed_pbatest.go, testdata/test-db.der,
// written by the demo launcher); the OS is signed with the matching key. sed_unlock
// is "none" so this demo isolates the Secure-Boot + trust-broker story (the mock
// SED unlock is shown by `task demo:linux`). Not part of normal or release builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
