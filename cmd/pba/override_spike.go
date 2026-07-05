//go:build tamago && amd64 && overridespike

package main

import (
	"fmt"
	"io"
	"unsafe"

	"github.com/walterchris/go-boot/uefi"
	"github.com/walterchris/go-boot/uefi/x64"
)

// securityStub is the EFI_SECURITY2_ARCH_PROTOCOL.FileAuthentication handler
// installed by the spike; its body is in override_spike_amd64.s. Firmware calls it
// (MS x64 ABI) during LoadImage. It is never called from Go — only its address is
// taken (securityStubAddr) and written into the firmware protocol.
func securityStub()

// securityStubAddr returns the raw entry address of securityStub (asm helper).
func securityStubAddr() uint64

// security2GUID is EFI_SECURITY2_ARCH_PROTOCOL_GUID
// (94ab2f58-1438-4ef1-9152-18941a3a0e68), the firmware image-authentication
// protocol that gBS->LoadImage consults under enforcing Secure Boot.
var security2GUID = uefi.MustParseGUID("94ab2f58-1438-4ef1-9152-18941a3a0e68")

// maybeOverrideSpike is the ADR-0012 / #82-task-1 go/no-go spike: it locates the
// firmware Security2 arch protocol and overwrites its FileAuthentication function
// pointer with our runtime-free asm stub. If firmware then calls the stub during
// the subsequent LoadImage — proven by an out-of-`db` image booting under enforcing
// Secure Boot — the SHIM-style override mechanism is viable in our stack.
//
// SPIKE ONLY: the stub authorizes unconditionally (a Secure Boot bypass). The
// production design (ADR-0012) authorizes exactly one pre-verified buffer by
// content memcmp and restores the original handler. Never ship this build.
func maybeOverrideSpike(w io.Writer) {
	addr, err := x64.UEFI.Boot.LocateProtocol(security2GUID)
	if err != nil {
		fmt.Fprintf(w, "%s: OVERRIDE-SPIKE: locate Security2 failed: %v\r\n", banner, err)
		return
	}
	// EFI_SECURITY2_ARCH_PROTOCOL has a single member, FileAuthentication, at
	// offset 0. Save the original pointer and install our stub in its place.
	slot := (*uint64)(unsafe.Pointer(uintptr(addr))) //nolint:govet // firmware protocol struct, identity-mapped
	orig := *slot
	*slot = securityStubAddr()
	fmt.Fprintf(w, "%s: OVERRIDE-SPIKE: Security2 @ 0x%x, FileAuthentication 0x%x -> stub 0x%x\r\n", banner, addr, orig, *slot)
}
