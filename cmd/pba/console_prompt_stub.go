//go:build !tamago

package main

import (
	"errors"

	"github.com/walterchris/trusted-pba/internal/credential"
)

// stubPrompter is the host build's placeholder Prompter: the real one is
// UEFI-backed and only exists under tamago. It always fails closed. Host tests
// that exercise the console path inject their own mock Prompter into the
// credential.Env rather than using this.
type stubPrompter struct{} //nolint:unused // host counterpart of the tamago-only Prompter; keeps the package buildable on host

// newConsolePrompter returns the host stub Prompter so the package builds on the
// host toolchain; it is not used by any real boot path (which is tamago-only —
// main.go references it there).
func newConsolePrompter() credential.Prompter { return stubPrompter{} } //nolint:unused // referenced only by the tamago build (main.go)

// Passphrase always fails closed on the host: there is no pre-boot console.
func (stubPrompter) Passphrase(string) ([]byte, error) { //nolint:unused // host stub method; the tamago build supplies the real one
	return nil, errors.New("console passphrase entry is only available in the UEFI (tamago) build")
}
