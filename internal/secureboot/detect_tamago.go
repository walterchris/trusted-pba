//go:build tamago && amd64

package secureboot

import (
	"fmt"

	"github.com/walterchris/go-boot/uefi"
	"github.com/walterchris/go-boot/uefi/x64"
)

// Detect reads the firmware Secure Boot state via UEFI Runtime Services. It
// returns an error rather than guessing if a variable cannot be read, so callers
// can fail closed.
//
// Limitation: go-boot's GetVariable does not surface EFI_NOT_FOUND as a sentinel
// (it returns an opaque status error), so Detect cannot distinguish "variable
// absent" (firmware with no Secure Boot support, effectively off) from a genuine
// read failure — both return an error. A caller that must tell these apart needs
// an upstream go-boot fix; Phase 3 enforcement should treat any Detect error as
// "not enforcing" and fail closed.
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
