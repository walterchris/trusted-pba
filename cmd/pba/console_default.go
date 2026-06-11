//go:build tamago && amd64 && !serialonly

package main

import (
	"io"
	"os"

	"github.com/walterchris/go-boot/uefi/x64"
)

// consoleSinks returns the console output sinks for the default build: the UEFI
// ConOut (os.Stdout, shown on the VGA/text console) and COM1 serial (x64.UART0,
// which QEMU's -serial backend reliably captures regardless of how the firmware
// routes its console). This is the single place sink composition lives; the
// `serialonly` build tag selects the COM1-only variant (console_serialonly.go).
//
// Sinks must only ever carry non-sensitive status text — the same never-log-
// secrets rule (CLAUDE.md, baseline §11) that governs every write to out.
func consoleSinks() []io.Writer {
	return []io.Writer{os.Stdout, x64.UART0}
}
