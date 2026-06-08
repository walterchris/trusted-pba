//go:build tamago && amd64

// Command pba is the Trusted PBA UEFI application.
//
// Phase 3 boot manager: it boots as a UEFI x86_64 application under TamaGo, reads
// the firmware Secure Boot state, loads the compiled-in boot policy, enforces it
// (incl. an optional Secure-Boot-required gate), selects a target, and chainloads
// it — failing closed on any error. Validation mode "firmware" lets the firmware
// validate the image (Windows path); "pba" validates the image itself with
// internal/imageverify against the embedded Secure Boot trust store before loading.
//
// The UEFI board layer (CPU + serial init, EFI System Table parsing, heap setup)
// is provided by go-boot's uefi/x64 package, which performs that bring-up
// automatically on import.
package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/usbarmory/go-boot/uefi"
	"github.com/usbarmory/go-boot/uefi/x64"
	"github.com/walterchris/trusted-pba/internal/boottime"
	"github.com/walterchris/trusted-pba/internal/policy"
	"github.com/walterchris/trusted-pba/internal/secureboot"
	"github.com/walterchris/trusted-pba/internal/truststore"
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
		return verifyAndLoad(e.Path)
	default:
		return fmt.Errorf("chainload failed: unknown validation mode %q", e.Validation)
	}
}

// verifyAndLoad runs PBA-side Authenticode validation against the embedded Secure
// Boot trust store, then loads + starts the image only if it is trusted. Any
// failure — read, trust-store load, or verification — fails closed.
//
// The image bytes are read once for verification; LoadImage re-reads the same path
// to hand firmware its SourceBuffer. Pre-boot is single-threaded with no concurrent
// process able to swap the file between the two reads, so that window is not a TOCTOU
// risk here; under enforcing Secure Boot firmware also re-validates on load. Loading
// from the already-verified buffer (needs a go-boot SourceBuffer entry point) is
// tracked in #46 as defense-in-depth for the Secure-Boot-off case.
func verifyAndLoad(target string) error {
	root, err := x64.UEFI.Root()
	if err != nil {
		return fmt.Errorf("chainload failed: open ESP: %w", err)
	}
	fmt.Fprintf(out, "%s: ESP opened\r\n", banner)

	image, err := fs.ReadFile(root, target)
	if err != nil {
		return fmt.Errorf("chainload failed: read %q: %w", target, err)
	}

	store, err := truststore.Load()
	if err != nil {
		return fmt.Errorf("chainload failed: trust store: %w", err)
	}
	if err := store.Verifier(boottime.Now()).Verify(image); err != nil {
		return fmt.Errorf("chainload failed: verify %q: %w", target, err)
	}
	fmt.Fprintf(out, "%s: pba-verified %s (trust set %s)\r\n", banner, target, truststore.TrustSet)

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

// halt stops the machine. It is reached after a completed chainload AND after any
// fail-closed decision (policy denial, Secure-Boot-required, unverified target,
// load failure), so it MUST NOT hand control back to the firmware boot manager —
// that would proceed to the next boot option, the "silently continue to another
// boot path" the threat model forbids (CLAUDE.md/AGENTS.md). It powers off via
// ResetSystem (QEMU exits on guest shutdown); if the firmware ignores that, it
// stops the CPU here permanently rather than returning via Boot.Exit.
//
// Making the on-error action (halt vs controlled reboot/shutdown) policy-
// configurable is tracked in #44 — any such option must stay fail-closed: a reboot
// re-runs the PBA, never the firmware's next boot entry.
func halt() {
	if err := x64.UEFI.Runtime.ResetSystem(uefi.EfiResetShutdown); err != nil {
		fmt.Fprintf(out, "%s: shutdown failed: %v; halting\r\n", banner, err)
	}
	for {
		// Dead stop: never return to the firmware boot order.
	}
}
