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

	"github.com/usbarmory/go-boot/uefi"
	"github.com/usbarmory/go-boot/uefi/x64"
)

// Version is overridden at link time via -ldflags "-X 'main.Version=...'".
var Version = "dev"

const banner = "TRUSTED-PBA"

// emit writes to both the UEFI ConOut console (visible on the VGA/text console)
// and COM1 (x64.UART0), which is the path QEMU's -serial backend reliably
// captures regardless of how the firmware routes its console.
func emit(s string) {
	fmt.Print(s)
	x64.UART0.Write([]byte(s))
}

func main() {
	// Disable the UEFI watchdog so the firmware does not auto-reboot on us.
	x64.UEFI.Boot.SetWatchdogTimer(0)

	emit(banner + ": start\r\n")
	emit(banner + ": version " + Version + "\r\n")
	// Stable success marker the test harness asserts on.
	emit(banner + ": phase-0 skeleton ok\r\n")
	emit(banner + ": halting\r\n")

	// Clean stop: power the machine off (QEMU exits on guest shutdown). This is
	// deterministic for tests and avoids the firmware boot manager chaining to
	// another boot entry. Later phases that chainload an OS will instead hand
	// control back to firmware / a loaded image rather than shutting down.
	x64.UEFI.Runtime.ResetSystem(uefi.EfiResetShutdown)

	// If ResetSystem unexpectedly returns, hand back to the firmware cleanly
	// rather than falling off the end of main (which has no OS to return to).
	x64.UEFI.Boot.Exit(0)
}
