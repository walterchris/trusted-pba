// Command pba is the Trusted PBA UEFI application.
//
// Phase 0 skeleton: it boots as a UEFI x86_64 application under TamaGo, emits
// start/version markers over the console and COM1 serial, and then halts cleanly
// (no panic, no reboot). Later phases add SED unlock, policy, and chainloading.
//
// The UEFI board layer (CPU + serial init, EFI System Table parsing, heap setup)
// is provided by go-boot's uefi/x64 package, which performs that bring-up
// automatically on import.

//go:build tamago && amd64

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/usbarmory/go-boot/uefi"
	"github.com/usbarmory/go-boot/uefi/x64"
)

// Version is overridden at link time via -ldflags "-X 'main.Version=...'".
var Version = "dev"

const banner = "TRUSTED-PBA"

// out fans console output to the UEFI ConOut (os.Stdout, shown on the VGA/text
// console) and COM1 serial (x64.UART0, which QEMU's -serial backend reliably
// captures regardless of how the firmware routes its console). The writer set is
// fixed for now; making it configurable is tracked in #29.
var out io.Writer = io.MultiWriter(os.Stdout, x64.UART0)

func main() {
	// Disable the UEFI watchdog so the firmware does not auto-reboot on us.
	// Errors from UEFI calls are never ignored (AGENTS.md); on this halt path they
	// are not actionable beyond reporting, so we surface them and continue.
	if err := x64.UEFI.Boot.SetWatchdogTimer(0); err != nil {
		fmt.Fprint(out, banner+": warn: could not disable watchdog: "+err.Error()+"\r\n")
	}

	fmt.Fprint(out, banner+": start\r\n")
	fmt.Fprint(out, banner+": version "+Version+"\r\n")
	// Stable success marker the test harness asserts on.
	fmt.Fprint(out, banner+": phase-0 skeleton ok\r\n")
	fmt.Fprint(out, banner+": halting\r\n")

	// Clean stop: power the machine off (QEMU exits on guest shutdown). This is
	// deterministic for tests and avoids the firmware boot manager chaining to
	// another boot entry.
	if err := x64.UEFI.Runtime.ResetSystem(uefi.EfiResetShutdown); err != nil {
		fmt.Fprint(out, banner+": shutdown failed: "+err.Error()+"\r\n")
	}

	// Phase-0 fallback ONLY: if ResetSystem returns, hand back to firmware rather
	// than falling off the end of main (which has no OS to return to). WARNING:
	// Boot.Exit returns control to the UEFI boot manager, which on real hardware
	// proceeds to the NEXT boot option — exactly the "silently continue to another
	// boot path" behavior the threat model forbids. Later phases (unlock/policy/
	// chainload) MUST re-evaluate this, not copy it.
	if err := x64.UEFI.Boot.Exit(0); err != nil {
		fmt.Fprint(out, banner+": exit failed: "+err.Error()+"\r\n")
	}
}
