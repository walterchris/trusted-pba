//go:build demowin

package policy

import _ "embed"

//go:embed policy_demowin.json
var defaultJSON []byte

// Default returns the demo policy for `task demo:windows`: require_secure_boot
// true and a "firmware"-validated chainload of the Windows Boot Manager at
// EFI/MICROSOFT/BOOT/BOOTMGFW.EFI. Per the project rule, the firmware (with the
// Microsoft db/dbx enrolled) validates Windows Boot Manager — the PBA does not
// pre-verify it — so the measured-boot chain (PCR 7) stays intact for BitLocker.
// sed_unlock is "none" so this demo isolates the Secure-Boot Windows handoff.
// Not part of normal or release builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
