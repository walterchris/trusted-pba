//go:build !tamago

package transport

import "errors"

// ErrUnavailable is returned by the host build, which has no UEFI firmware. The
// real carrier exists only under TamaGo; off-target builds fail closed.
var ErrUnavailable = errors.New("transport: UEFI storage security unavailable off-target")

// UEFI is the off-target placeholder so the package builds and the opal.Transport
// assertion holds on the host.
type UEFI struct{}

// New always fails on the host (no firmware).
func New() (*UEFI, error) { return nil, ErrUnavailable }

// Send always fails on the host.
func (u *UEFI) Send(_ uint8, _ uint16, _ []byte) error { return ErrUnavailable }

// Recv always fails on the host.
func (u *UEFI) Recv(_ uint8, _ uint16, _ int) ([]byte, error) { return nil, ErrUnavailable }
