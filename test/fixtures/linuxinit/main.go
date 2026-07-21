//go:build linux

// TEST TOOLING ONLY (linux-boot matrix, test/qemu/linux-boot-matrix.sh).
//
// A minimal PID-1 for the matrix's initramfs: prove that a real Linux kernel,
// chainloaded by the PBA after the SED unlock, reached userspace — then power
// the guest off so the harness run ends deterministically. It is built with the
// HOST Go toolchain (CGO_ENABLED=0, static) by test/qemu/build-linux-uki.sh and
// packed as /init into the UKI's initramfs. NOT product code.
package main

import (
	"os"
	"syscall"
	"time"
)

// marker is asserted by expect-serial.py (REQUIRE in the positive scenarios,
// FORBID in the fail-closed ones: a locked drive must never boot an OS).
const marker = "TEST-LINUX: userspace ok\r\n"

func main() {
	// Best-effort: the initramfs carries an empty /dev; mount devtmpfs so the
	// console/serial nodes exist. Ignore failure — the kernel may have mounted
	// it already (CONFIG_DEVTMPFS_MOUNT), and the write below is what matters.
	_ = syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, "")

	// Write the marker to the first console that opens. /dev/console is the
	// kernel console (ttyS0 via the UKI cmdline); ttyS0 is the direct fallback.
	for _, path := range []string{"/dev/console", "/dev/ttyS0"} {
		f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // G304: path is from a fixed list of console device nodes
		if err != nil {
			continue
		}
		_, err = f.WriteString(marker)
		_ = f.Close() // write success is the signal; Close on a tty buffers nothing
		if err == nil {
			break
		}
	}

	// Let the UART drain, then power off: QEMU exits and the harness judges the
	// markers seen so far. If power-off is unavailable, park forever — the
	// harness's timeout/grace teardown reclaims the guest either way.
	time.Sleep(2 * time.Second)
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}
