//go:build tamago && amd64

package main

import (
	"errors"
	"time"

	"github.com/walterchris/go-boot/uefi"
	"github.com/walterchris/go-boot/uefi/x64"
	"github.com/walterchris/trusted-pba/internal/credential"
)

// uefiPrompter reads an interactive passphrase over the UEFI Simple Text Input
// protocol (via go-boot's console). It is the concrete credential.Prompter the
// tamago entrypoint supplies in the credential.Env; the console credential source
// consumes it without knowing it is UEFI-backed (credential stays UEFI-free).
type uefiPrompter struct{}

// newConsolePrompter returns the real UEFI-backed Prompter for the boot path.
func newConsolePrompter() credential.Prompter { return uefiPrompter{} }

// errPassphraseTooLong is returned when the input line exceeds maxPassphraseLen
// before a line terminator; it fails closed rather than truncating a secret.
var errPassphraseTooLong = errors.New("passphrase too long")

// Passphrase writes prompt to the console and reads a line of input over UEFI
// SimpleTextInput without echoing the characters (it echoes '*' for feedback).
// It terminates on CR or LF, handles backspace, and caps the line length. It
// returns the entered ASCII bytes; the caller owns and zeroizes them. On any
// input error (or over-length line) it zeroizes the partial buffer and fails
// closed, returning no secret in the error.
//
// UEFI status handling: Console.Input returns EFI_NOT_READY (low byte) when no
// key is buffered yet — we poll rather than treat it as an error; any other
// non-success status is a hard input error.
func (uefiPrompter) Passphrase(prompt string) (out []byte, err error) {
	con := x64.UEFI.Console
	if con == nil {
		return nil, errors.New("no UEFI console")
	}
	_, _ = con.Write([]byte(prompt))

	// Pre-allocate the accumulator so append never reallocates and strands
	// un-scrubbed passphrase-prefix copies — see newPassphraseBuf (#124, R-003).
	out = newPassphraseBuf()

	// Zeroize the accumulator on any error path so a partial passphrase never
	// escapes un-scrubbed (#101 carry-over; ADR-0011 §5). On the success path we
	// hand the buffer to the caller, so only clear it when returning an error.
	defer func() {
		if err != nil {
			clear(out)
			out = nil
		}
	}()

	var key uefi.InputKey
	for {
		status := con.Input(&key)
		switch {
		case status&0xff == uefi.EFI_NOT_READY:
			// No key buffered yet; sleep before polling again so the wait for
			// operator keystrokes does not busy-spin and starve the TamaGo
			// scheduler (mirrors go-boot's Console.Read).
			time.Sleep(10 * time.Millisecond)
			continue
		case status != uefi.EFI_SUCCESS:
			return out, errors.New("console input error")
		}

		ch := key.UnicodeChar[0]
		switch ch {
		case cr, lf:
			_, _ = con.Write([]byte("\r\n"))
			return out, nil
		case bs:
			if len(out) > 0 {
				out[len(out)-1] = 0
				out = out[:len(out)-1]
				_, _ = con.Write([]byte("\b \b"))
			}
			continue
		case 0:
			// A control/scan-code key (no ASCII) — ignore.
			continue
		}
		if len(out) >= maxPassphraseLen {
			return out, errPassphraseTooLong
		}
		out = append(out, ch)
		_, _ = con.Write([]byte{'*'})
	}
}

// ASCII control characters used for line editing.
const (
	bs = 0x08 // backspace
	lf = 0x0a // line feed
	cr = 0x0d // carriage return
)
