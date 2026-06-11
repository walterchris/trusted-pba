//go:build tamago && amd64

// Command pba is the Trusted PBA UEFI application.
//
// It boots as a UEFI x86_64 application under TamaGo, reads the firmware Secure
// Boot state, loads the compiled-in boot policy, enforces it (incl. an optional
// Secure-Boot-required gate), unlocks the Opal SED when the policy demands it
// (sed_unlock, ADR-0009), selects a target, and chainloads it — failing closed on
// any error. Validation mode "firmware" lets the firmware validate the image
// (Windows path); "pba" validates the image itself with internal/imageverify
// against the embedded Secure Boot trust store before loading.
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

	"github.com/walterchris/go-boot/uefi"
	"github.com/walterchris/go-boot/uefi/x64"
	"github.com/walterchris/trusted-pba/internal/opal"
	"github.com/walterchris/trusted-pba/internal/policy"
	"github.com/walterchris/trusted-pba/internal/secureboot"
	"github.com/walterchris/trusted-pba/internal/transport"
	"github.com/walterchris/trusted-pba/internal/truststore"
)

// Version is overridden at link time via -ldflags "-X 'main.Version=...'".
var Version = "dev"

// bootPolicy is go-boot's LoadImage "boot" argument: 0 means BootPolicy = FALSE —
// the image is loaded by us, not via the firmware boot-manager device-path policy.
const bootPolicy = 0

// chainloadFail is the single source of the "chainload failed" prefix that every
// chainload error path carries. The QEMU harness greps it as a fail-closed oracle
// (test/qemu/pba-run.sh); single-sourcing it stops a per-site typo from silently
// decoupling one path from that contract.
const chainloadFail = "chainload failed"

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

	// Until the policy is loaded the only safe terminal action is halt.
	mode := policy.OnErrorHalt

	pol, err := policy.Default()
	if err != nil {
		fmt.Fprintf(out, "%s: policy load failed: %v\r\n", banner, err)
		terminate(mode)
		return
	}
	mode = pol.OnError

	if err := run(pol, secureBootEnforcing()); err != nil {
		// Fail closed: report and carry out the policy's on-error action. Never
		// continue as if the boot succeeded.
		fmt.Fprintf(out, "%s: %v\r\n", banner, err)
		terminate(mode)
		return
	}

	fmt.Fprintf(out, "%s: chainload returned\r\n", banner)
	terminate(mode)
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

// run enforces the policy, unlocks the SED when required, selects a target, and
// chainloads it. The unlock comes before any target selection/chainload: on an
// unlock error this returns — main terminates via the on-error action — and never
// proceeds or retries into boot (#51 item 2).
func run(pol *policy.Policy, enforcing bool) error {
	if err := pol.CheckSecureBoot(enforcing); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if err := unlockSED(pol, newUEFITransport, out); err != nil {
		return err
	}
	entry, err := pol.Select()
	if err != nil {
		return fmt.Errorf("policy: no bootable target: %w", err)
	}
	fmt.Fprintf(out, "%s: target %q (%s) via %s\r\n", banner, entry.Name, entry.Path, entry.Validation)
	return chainload(entry)
}

// newUEFITransport adapts transport.New to the opal.Transport constructor shape
// unlockSED takes. It fails closed when the firmware exposes no Storage Security
// device.
func newUEFITransport() (opal.Transport, error) {
	t, err := transport.New()
	if err != nil {
		return nil, err
	}
	return t, nil
}

// chainload dispatches on the entry's validation mode. All error returns are
// prefixed chainloadFail so the top-level fail-closed handler is greppable.
func chainload(e policy.BootEntry) error {
	switch e.Validation {
	case policy.Firmware:
		return load(e.Path)
	case policy.PBA:
		return verifyAndLoad(e.Path)
	default:
		return fmt.Errorf("%s: unknown validation mode %q", chainloadFail, e.Validation)
	}
}

// verifyAndLoad runs PBA-side Authenticode validation against the embedded Secure
// Boot trust store, then loads + starts the image only if it is trusted. Any
// failure — read, trust-store load, or verification — fails closed.
//
// Invariant (verified buffer == executed buffer): the image bytes are read exactly
// once into image, verified, and that same buffer is handed to the firmware via
// LoadImageBuffer as the LoadImage SourceBuffer. The firmware never re-reads the
// file, so there is no verify-then-load window even with Secure Boot off; under
// enforcing Secure Boot the firmware additionally re-validates the buffer on load.
// A single path string (target) feeds read, verification reporting, and the device
// path passed to LoadImageBuffer.
func verifyAndLoad(target string) error {
	root, err := x64.UEFI.Root()
	if err != nil {
		return fmt.Errorf("%s: open ESP: %w", chainloadFail, err)
	}
	if root == nil {
		// Dead code against the current pinned fork (Root() never returns a nil
		// root with a nil error); kept against future fork changes, since both
		// fs.ReadFile and LoadImageBuffer→root.FilePath dereference root.
		return fmt.Errorf("%s: open ESP: nil root volume", chainloadFail)
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

	img, err := x64.UEFI.Boot.LoadImageBuffer(root, target, image)
	if err != nil {
		// Discard img unconditionally: firmware may return a valid handle
		// alongside EFI_SECURITY_VIOLATION; it must never be started or kept.
		return fmt.Errorf("%s: load %q: %w", chainloadFail, target, err)
	}
	fmt.Fprintf(out, "%s: starting %s\r\n", banner, target)

	if err := x64.UEFI.Boot.StartImage(img); err != nil {
		return fmt.Errorf("%s: start %q: %w", chainloadFail, target, err)
	}
	return nil
}

// load opens the EFI System Partition and loads + starts the image at the given
// ESP-relative path, letting the firmware (Secure Boot) validate it.
func load(target string) error {
	root, err := x64.UEFI.Root()
	if err != nil {
		return fmt.Errorf("%s: open ESP: %w", chainloadFail, err)
	}
	fmt.Fprintf(out, "%s: ESP opened\r\n", banner)

	if root == nil {
		// Defense-in-depth, mirroring verifyAndLoad: dead against the current
		// pinned fork (Root() never returns a nil root with a nil error), kept
		// because LoadImage dereferences root.
		return fmt.Errorf("%s: open ESP: nil root volume", chainloadFail)
	}

	img, err := x64.UEFI.Boot.LoadImage(bootPolicy, root, target)
	if err != nil {
		return fmt.Errorf("%s: load %q: %w", chainloadFail, target, err)
	}
	fmt.Fprintf(out, "%s: starting %s\r\n", banner, target)

	if err := x64.UEFI.Boot.StartImage(img); err != nil {
		return fmt.Errorf("%s: start %q: %w", chainloadFail, target, err)
	}
	return nil
}

// terminate carries out the policy's fail-closed on-error action. It is reached
// after a completed chainload AND after any fail-closed decision (policy denial,
// Secure-Boot-required, unverified target, load failure), so it MUST NOT hand
// control back to the firmware boot manager — that would proceed to the next boot
// option, the "silently continue to another boot path" the threat model forbids
// (CLAUDE.md/AGENTS.md). Every mode therefore ends at the dead-stop, never at
// Boot.Exit:
//   - halt (default): stop the CPU.
//   - shutdown: power off via ResetSystem (QEMU exits on guest shutdown).
//   - reboot: reset via ResetSystem, which re-runs the PBA from the start — never
//     the firmware's next boot entry.
//
// A failed ResetSystem falls through to the dead-stop, so control is never handed
// back regardless of mode.
func terminate(mode policy.OnError) {
	switch mode {
	case policy.OnErrorReboot:
		fmt.Fprintf(out, "%s: rebooting\r\n", banner)
		if err := x64.UEFI.Runtime.ResetSystem(uefi.EfiResetCold); err != nil {
			fmt.Fprintf(out, "%s: reset failed: %v; halting\r\n", banner, err)
		}
	case policy.OnErrorShutdown:
		fmt.Fprintf(out, "%s: powering off\r\n", banner)
		if err := x64.UEFI.Runtime.ResetSystem(uefi.EfiResetShutdown); err != nil {
			fmt.Fprintf(out, "%s: shutdown failed: %v; halting\r\n", banner, err)
		}
	}
	for {
		// Dead stop: never return to the firmware boot order.
	}
}
