//go:build tamago && amd64

// Command pba is the Trusted PBA UEFI application.
//
// Phase 1 boot-manager MVP: it boots as a UEFI x86_64 application under TamaGo,
// opens the EFI System Partition it was loaded from, then loads and starts a
// second-stage EFI image (chainload), and halts. Any failure fails closed — the
// PBA never reports success or continues as if the chainload worked. Later phases
// add SED unlock and a policy engine in front of the chainload.
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
	"github.com/walterchris/trusted-pba/internal/secureboot"
)

// Version is overridden at link time via -ldflags "-X 'main.Version=...'".
var Version = "dev"

// Target is the ESP-relative path of the second-stage image to chainload.
// Overridable at link time via -ldflags "-X 'main.Target=...'". Phase 1 loads a
// test fixture; later phases select this via the policy engine.
var Target = "EFI/TEST/TESTAPP.EFI"

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
	// UEFI errors are never ignored (AGENTS.md); on this path they are not
	// actionable beyond reporting, so we surface them and continue.
	if err := x64.UEFI.Boot.SetWatchdogTimer(0); err != nil {
		fmt.Fprintf(out, "%s: warn: could not disable watchdog: %v\r\n", banner, err)
	}

	fmt.Fprintf(out, "%s: start\r\n", banner)
	fmt.Fprintf(out, "%s: version %s\r\n", banner, Version)

	// Report firmware Secure Boot state. Phase 2 is detection + reporting only;
	// enforcing a policy (e.g. refusing to proceed when not enforcing) is a later
	// decision tied to the policy engine. See #35 and ADR-0003.
	if st, err := secureboot.Detect(); err != nil {
		fmt.Fprintf(out, "%s: secure-boot: detection failed: %v\r\n", banner, err)
	} else {
		fmt.Fprintf(out, "%s: secure-boot: %s\r\n", banner, st)
	}

	if err := chainload(Target); err != nil {
		// Fail closed: report and halt. Never continue as if the boot succeeded.
		fmt.Fprintf(out, "%s: chainload failed: %v\r\n", banner, err)
		halt()
		return
	}

	fmt.Fprintf(out, "%s: chainload returned\r\n", banner)
	halt()
}

// chainload opens the EFI System Partition the PBA was loaded from and loads then
// starts the second-stage image at the given ESP-relative path. It returns an
// error (rather than printing/continuing) so the caller can fail closed.
func chainload(target string) error {
	root, err := x64.UEFI.Root()
	if err != nil {
		return fmt.Errorf("open ESP: %w", err)
	}
	fmt.Fprintf(out, "%s: ESP opened\r\n", banner)

	// SECURITY (Phase 1): no image verification or Secure Boot enforcement is done
	// before loading the target — that trust gate is added in Phase 2 (Secure Boot)
	// and Phase 3 (policy engine). This build is CI/dev-only until then; it must not
	// gate a real boot. See docs/architecture/adr/ADR-0006-chainload-mechanism.md.
	img, err := x64.UEFI.Boot.LoadImage(bootPolicy, root, target)
	if err != nil {
		return fmt.Errorf("load %q: %w", target, err)
	}
	fmt.Fprintf(out, "%s: starting %s\r\n", banner, target)

	if err := x64.UEFI.Boot.StartImage(img); err != nil {
		return fmt.Errorf("start %q: %w", target, err)
	}
	return nil
}

// halt stops the machine cleanly: it powers off via ResetSystem (QEMU exits on
// guest shutdown). If that returns, it hands back to firmware as a last resort.
//
// WARNING: Boot.Exit returns control to the UEFI boot manager, which on real
// hardware proceeds to the NEXT boot option — the "silently continue" behavior
// the threat model forbids. It is a fallback only; later phases that gate the
// chainload on SED unlock/policy MUST re-evaluate this, not copy it.
func halt() {
	if err := x64.UEFI.Runtime.ResetSystem(uefi.EfiResetShutdown); err != nil {
		fmt.Fprintf(out, "%s: shutdown failed: %v\r\n", banner, err)
	}
	if err := x64.UEFI.Boot.Exit(0); err != nil {
		fmt.Fprintf(out, "%s: exit failed: %v\r\n", banner, err)
	}
}
