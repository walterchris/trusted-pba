//go:build tamago && amd64

package secureboot

import (
	"fmt"

	"github.com/usbarmory/go-boot/uefi"
	"github.com/usbarmory/go-boot/uefi/x64"
)

// Detect reads the firmware Secure Boot state via UEFI Runtime Services. It
// returns an error rather than guessing if a variable cannot be read, so callers
// can fail closed.
func Detect() (State, error) {
	sb, err := readU8("SecureBoot")
	if err != nil {
		return State{}, fmt.Errorf("read SecureBoot: %w", err)
	}
	setup, err := readU8("SetupMode")
	if err != nil {
		return State{}, fmt.Errorf("read SetupMode: %w", err)
	}
	return State{SecureBoot: sb == 1, SetupMode: setup == 1}, nil
}

// readU8 reads a single-byte global UEFI variable (SecureBoot/SetupMode are UINT8).
func readU8(name string) (byte, error) {
	_, data, err := x64.UEFI.Runtime.GetVariable(name, uefi.EFI_GLOBAL_VARIABLE_GUID, true)
	if err != nil {
		return 0, err
	}
	if len(data) < 1 {
		return 0, fmt.Errorf("variable %q: empty", name)
	}
	return data[0], nil
}
