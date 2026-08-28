//go:build demowin

package policy

import _ "embed"

//go:embed policy_demowin.json
var defaultJSON []byte

// Default returns the demo policy for `task demo:windows`: require_secure_boot
// true, a console-credential mock SED unlock, then a "pba-override"-validated
// chainload of the Windows Boot Manager at EFI/MICROSOFT/BOOT/BOOTMGFW.EFI. This is
// the Key-A-only override model (ADR-0013): firmware db holds only our key, so the
// PBA trust-brokers Windows Boot Manager against the Microsoft Windows CAs in its
// embedded trust store (the windows-only set covers it) and admits it via the
// shim-style Security2 override. Because the override authorizes the load without a
// firmware db authority, PCR 7 diverges from a native boot — BitLocker must be
// sealed with the PBA in-chain (ADR-0013). Requires the trustbroker build tag; not
// part of normal or release builds.
func Default() (*Policy, error) {
	return Parse(defaultJSON)
}
