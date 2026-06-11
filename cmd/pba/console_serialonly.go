//go:build tamago && amd64 && serialonly

package main

import (
	"io"

	"github.com/walterchris/go-boot/uefi/x64"
)

// consoleSinks (serialonly build) fans output to COM1 serial only (x64.UART0),
// dropping the UEFI ConOut text console. Useful for headless / CI runs where the
// VGA console is redundant with the captured serial and only adds interleaving
// noise. Same never-log-secrets rule as the default set.
func consoleSinks() []io.Writer {
	return []io.Writer{x64.UART0}
}
