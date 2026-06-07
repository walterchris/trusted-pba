//go:build tamago && amd64

// Command pba is the Trusted PBA UEFI application.
//
// Phase 3 boot manager: it boots as a UEFI x86_64 application under TamaGo, reads
// the firmware Secure Boot state, loads the compiled-in boot policy, enforces it
// (incl. an optional Secure-Boot-required gate), selects a target, and chainloads
// it — failing closed on any error. Validation mode "firmware" lets the firmware
// validate the image (Windows path); "pba" (PBA-side Authenticode validation) is
// implemented in #41 and until then fails closed.
//
// The UEFI board layer (CPU + serial init, EFI System Table parsing, heap setup)
// is provided by go-boot's uefi/x64 package, which performs that bring-up
// automatically on import.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/usbarmory/go-boot/uefi"
	"github.com/usbarmory/go-boot/uefi/x64"
	"github.com/walterchris/trusted-pba/internal/policy"
	"github.com/walterchris/trusted-pba/internal/secureboot"
)

// Version is overridden at link time via -ldflags "-X 'main.Version=...'".
var Version = "dev"

const banner = "TRUSTED-PBA"

// bootPolicy is go-boot's LoadImage "boot" argument: 0 means BootPolicy = FALSE —
// the image is loaded by us, not via the firmware boot-manager device-path policy.
const bootPolicy = 0

// out fans console output to the UEFI ConOut (os.Stdout, shown on the VGA/text
// console) and COM1 serial (x64.UART0, which QEMU's -serial backend reliably
// captures regardless of how the firmware routes its console). The writer set is
// fixed for now; making it configurable is tracked in #29.
var out io.Writer = io.MultiWriter(os.Stdout, x64.UART0)

func main() {
	// Disable the UEFI watchdog so the firmware does not auto-reboot on us.
	if err := x64.UEFI.Boot.SetWatchdogTimer(0); err != nil {
		fmt.Fprintf(out, "%s: warn: could not disable watchdog: %v\r\n", banner, err)
	}

	fmt.Fprintf(out, "%s: start\r\n", banner)
	fmt.Fprintf(out, "%s: version %s\r\n", banner, Version)

	if err := run(secureBootEnforcing()); err != nil {
		// Fail closed: report and halt. Never continue as if the boot succeeded.
		fmt.Fprintf(out, "%s: %v\r\n", banner, err)
		halt()
		return
	}

	fmt.Fprintf(out, "%s: chainload returned\r\n", banner)
	halt()
}

// secureBootEnforcing reports + returns whether the firmware is enforcing Secure
// Boot. A detection failure is reported and treated as "not enforcing"; the policy
// (require_secure_boot) decides whether that is fatal.
func secureBootEnforcing() bool {
	st, err := secureboot.Detect()
	if err != nil {
		fmt.Fprintf(out, "%s: secure-boot: detection failed: %v\r\n", banner, err)
		return false
	}
	fmt.Fprintf(out, "%s: secure-boot: %s\r\n", banner, st)
	return st.Enforcing()
}

// run loads the policy, enforces it, selects a target, and chainloads it.
func run(enforcing bool) error {
	pol, err := policy.Default()
	if err != nil {
		return fmt.Errorf("policy load failed: %w", err)
	}
	if err := pol.CheckSecureBoot(enforcing); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	entry, err := pol.Select()
	if err != nil {
		return fmt.Errorf("policy: no bootable target: %w", err)
	}
	fmt.Fprintf(out, "%s: target %q (%s) via %s\r\n", banner, entry.Name, entry.Path, entry.Validation)
	return chainload(entry)
}

// chainload dispatches on the entry's validation mode. All error returns are
// prefixed "chainload failed" so the top-level fail-closed handler is greppable.
func chainload(e policy.BootEntry) error {
	switch e.Validation {
	case policy.Firmware:
		return load(e.Path)
	case policy.PBA:
		// PBA-side Authenticode verification lands in #41; until then, fail closed.
		return fmt.Errorf("chainload failed: pba validation for %q not yet implemented", e.Path)
	default:
		return fmt.Errorf("chainload failed: unknown validation mode %q", e.Validation)
	}
}

// load opens the EFI System Partition and loads + starts the image at the given
// ESP-relative path, letting the firmware (Secure Boot) validate it.
func load(target string) error {
	root, err := x64.UEFI.Root()
	if err != nil {
		return fmt.Errorf("chainload failed: open ESP: %w", err)
	}
	fmt.Fprintf(out, "%s: ESP opened\r\n", banner)

	img, err := x64.UEFI.Boot.LoadImage(bootPolicy, root, target)
	if err != nil {
		return fmt.Errorf("chainload failed: load %q: %w", target, err)
	}
	fmt.Fprintf(out, "%s: starting %s\r\n", banner, target)

	if err := x64.UEFI.Boot.StartImage(img); err != nil {
		return fmt.Errorf("chainload failed: start %q: %w", target, err)
	}
	return nil
}

// halt stops the machine cleanly: it powers off via ResetSystem (QEMU exits on
// guest shutdown). If that returns, it hands back to firmware as a last resort.
//
// WARNING: Boot.Exit returns control to the UEFI boot manager, which on real
// hardware proceeds to the NEXT boot option — the "silently continue" behavior the
// threat model forbids. It is a fallback only; the policy/unlock phases must not
// rely on it.
func halt() {
	if err := x64.UEFI.Runtime.ResetSystem(uefi.EfiResetShutdown); err != nil {
		fmt.Fprintf(out, "%s: shutdown failed: %v\r\n", banner, err)
	}
	if err := x64.UEFI.Boot.Exit(0); err != nil {
		fmt.Fprintf(out, "%s: exit failed: %v\r\n", banner, err)
	}
}
