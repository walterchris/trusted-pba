//go:build tamago && amd64 && trustbroker

package main

import (
	"fmt"
	"io/fs"
	"unsafe"

	"github.com/walterchris/go-boot/uefi"
	"github.com/walterchris/go-boot/uefi/x64"
	"github.com/walterchris/trusted-pba/internal/truststore"
)

// Security2-override state (ADR-0012). securityStub (override_trustbroker_amd64.s)
// reads these; installOverride writes them. Single-writer: the PBA is single-
// goroutine and pre-boot, and `sbArmed` is written last as the release gate the
// stub tests first, so the stub never observes a half-armed record.
var (
	sbArmed   uint64 // 1 = authorize the pinned buffer once
	sbBufPtr  uint64 // &image[0] the PBA verified
	sbBufSize uint64 // len(image)
	sbSavedFn uint64 // original firmware FileAuthentication, tail-called on any mismatch
)

// securityStub is installed as EFI_SECURITY2_ARCH_PROTOCOL.FileAuthentication;
// its body is in override_trustbroker_amd64.s. Firmware calls it (MS x64 ABI) on
// LoadImage. Never called from Go — only its address is taken (securityStubAddr).
func securityStub()

// securityStubAddr returns the raw entry address of securityStub (asm helper).
func securityStubAddr() uint64

// security2GUID is EFI_SECURITY2_ARCH_PROTOCOL_GUID — the firmware image-auth
// protocol gBS->LoadImage consults under enforcing Secure Boot.
var security2GUID = uefi.MustParseGUID("94ab2f58-1438-4ef1-9152-18941a3a0e68")

// verifyAndLoadOverride is the pba-override path (ADR-0012): the PBA verifies the
// image against its embedded trust store, then authorizes exactly that buffer to
// the firmware via a Security2 override so it loads even when firmware db would
// reject it (e.g. an our-keys-only platform booting an MS-signed loader). Every
// error fails closed; the override is armed for one matching buffer and self-disarms.
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
// FileAuthentication pointer, arms the stub to authorize exactly [ptr,size) once,
// and installs the stub. It fails closed if the protocol is absent. The returned
// restore func reinstalls the original handler and disarms; call it (deferred).
func installOverride(ptr *byte, size int) (restore func(), err error) {
	addr, err := x64.UEFI.Boot.LocateProtocol(security2GUID)
	if err != nil {
		return nil, fmt.Errorf("locate Security2: %w", err)
	}
	slot := (*uint64)(unsafe.Pointer(uintptr(addr))) // FileAuthentication at offset 0
	sbSavedFn = *slot
	sbBufPtr = uint64(uintptr(unsafe.Pointer(ptr)))
	sbBufSize = uint64(size)
	sbArmed = 1                // release gate: the stub authorizes only after this
	*slot = securityStubAddr() // install
	fmt.Fprintf(out, "%s: override armed (Security2 @ 0x%x, buf 0x%x/%d)\r\n", banner, addr, sbBufPtr, size)
	return func() {
		*slot = sbSavedFn // reinstall the firmware handler
		sbArmed = 0       // disarm
	}, nil
}
