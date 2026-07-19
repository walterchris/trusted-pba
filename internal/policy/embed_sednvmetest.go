//go:build sednvmetest

package policy

import _ "embed"

//go:embed policy_sednvme.json
var defaultJSON []byte

// Default returns a test policy with sed_unlock "required" and the sedutil-pbkdf2
// derive stage in "auto" iteration mode (#110/#112), embedded only in the
// `-tags sednvmetest` build used by the QEMU NVMe-passthru Opal matrix. The
// derive makes the boot path select the NVMe-passthru carrier (the only one
// exposing the drive serial the PBKDF2 salt needs); the mock drive is
// provisioned at 75000 iterations, so auto must advance past its first
// candidate (500000) — the real-world hash-provisioned shape. on_error is
// "halt" so a failed run ends deterministically for the serial harness. Not
// part of normal builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
