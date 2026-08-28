//go:build tamago && amd64 && trustbroker

package main

import (
	"fmt"
	"io/fs"
	"unsafe"

	"github.com/walterchris/go-boot/uefi"
	"github.com/walterchris/go-boot/uefi/x64"
	"github.com/walterchris/trusted-pba/internal/tbstub"
	"github.com/walterchris/trusted-pba/internal/truststore"
)

// security2GUID is EFI_SECURITY2_ARCH_PROTOCOL_GUID — the firmware image-auth
// protocol gBS->LoadImage consults under enforcing Secure Boot.
var security2GUID = uefi.MustParseGUID("94ab2f58-1438-4ef1-9152-18941a3a0e68")

// verifyAndLoadOverride is the pba-override path (ADR-0012): the PBA verifies the
// image against its embedded trust store, then authorizes exactly that buffer to
// the firmware via a Security2 override (internal/tbstub) so it loads even when
// firmware db would reject it (e.g. an our-keys-only platform booting an MS-signed
// loader). Every error fails closed; the override is armed for one matching buffer
// and self-disarms.
//
// NOTE (ADR-0012): this diverges PCR 7 — do not use for BitLocker/measured-boot
// targets; those use firmware-db validation (mode "firmware"/"pba").
func verifyAndLoadOverride(target string, enforcing bool) error {
	// The override makes the PBA's verdict authoritative for the firmware's load; it
	// is only reasoned safe under ENFORCING Secure Boot (ADR-0012/0013). Refuse to
	// arm otherwise — fail closed, defence-in-depth beyond require_secure_boot.
	if !enforcing {
		return fmt.Errorf("%s: pba-override requires enforcing Secure Boot", chainloadFail)
	}
	root, err := x64.UEFI.Root()
	if err != nil {
		return fmt.Errorf("%s: open ESP: %w", chainloadFail, err)
	}
	fmt.Fprintf(out, "%s: ESP opened\r\n", banner)

	image, err := fs.ReadFile(root, target)
	if err != nil {
		return fmt.Errorf("%s: read %q: %w", chainloadFail, target, err)
	}
	store, err := truststore.Load()
	if err != nil {
		return fmt.Errorf("%s: trust store: %w", chainloadFail, err)
	}
	if err := store.Verifier().Verify(image); err != nil {
		return fmt.Errorf("%s: verify %q: %w", chainloadFail, target, err)
	}
	fmt.Fprintf(out, "%s: pba-verified %s (trust set %s)\r\n", banner, target, truststore.TrustSet)

	restore, err := installOverride(&image[0], len(image))
	if err != nil {
		return fmt.Errorf("%s: override: %w", chainloadFail, err)
	}
	// Reinstall the firmware handler + disarm on every return path. (On a real OS
	// StartImage does not return, but the stub also self-disarms after its one
	// authorization, so the override is never left live regardless.)
	defer restore()

	img, err := x64.UEFI.Boot.LoadImageBuffer(root, target, image)
	if err != nil {
		return fmt.Errorf("%s: load %q: %w", chainloadFail, target, err)
	}
	fmt.Fprintf(out, "%s: starting %s (override)\r\n", banner, target)

	if err := x64.UEFI.Boot.StartImage(img); err != nil {
		return fmt.Errorf("%s: start %q: %w", chainloadFail, target, err)
	}
	return nil
}

// installOverride locates the firmware Security2 arch protocol, saves its
// FileAuthentication pointer, arms the tbstub to authorize exactly [ptr,size) once,
// and installs the stub. It fails closed if the protocol is absent. The returned
// restore func reinstalls the original handler and disarms; call it (deferred).
//
// Security2 only — not the legacy EFI_SECURITY_ARCH_PROTOCOL (#92): a UEFI 2.3.1+
// DXE core consults EFI_SECURITY2_ARCH_PROTOCOL.FileAuthentication for LoadImage
// under Secure Boot; FileAuthenticationState is the pre-2.3.1 path. SHIM hooks
// both for broad legacy-firmware reach the PBA (a modern-UEFI target) does not
// need, and hooking a second protocol only widens the authorization surface.
// Crucially, omitting the legacy hook is fail-closed, not fail-open: on the
// hypothetical firmware that authenticated via the legacy protocol only, our
// stub simply never fires, so the out-of-db image is rejected by firmware — a
// boot failure, never a silent authorization. The enforcing-SB precondition and
// verify-before-arm gate hold regardless of which protocol firmware calls.
func installOverride(ptr *byte, size int) (restore func(), err error) {
	addr, err := x64.UEFI.Boot.LocateProtocol(security2GUID)
	if err != nil {
		return nil, fmt.Errorf("locate Security2: %w", err)
	}
	slot := (*uint64)(unsafe.Pointer(uintptr(addr))) // FileAuthentication at offset 0
	orig := *slot
	tbstub.Arm(uintptr(unsafe.Pointer(ptr)), uint64(size), orig)
	*slot = tbstub.StubAddr() // install
	fmt.Fprintf(out, "%s: override armed (Security2 @ 0x%x, buf 0x%x/%d)\r\n",
		banner, addr, uintptr(unsafe.Pointer(ptr)), size)
	return func() {
		*slot = orig // reinstall the firmware handler
		tbstub.Disarm()
	}, nil
}
