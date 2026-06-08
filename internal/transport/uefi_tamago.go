//go:build tamago && amd64

package transport

import (
	"fmt"

	"github.com/walterchris/go-boot/uefi/x64"
)

// defaultTimeout is the SendData/ReceiveData timeout in 100 ns units; 0 means the
// firmware default (no explicit timeout).
const defaultTimeout = 0

// UEFI carries Opal IF-SEND/IF-RECV over the firmware
// EFI_STORAGE_SECURITY_COMMAND_PROTOCOL.
type UEFI struct {
	ssc     storageSecurity
	mediaID uint32
	timeout uint64
}

// storageSecurity is the slice of go-boot's protocol the transport uses (defined
// for testability/clarity; satisfied by *uefi.StorageSecurity).
type storageSecurity interface {
	SendData(mediaID uint32, timeout uint64, securityProtocol uint8, spSpecific uint16, payload []byte) error
	ReceiveData(mediaID uint32, timeout uint64, securityProtocol uint8, spSpecific uint16, size int) ([]byte, error)
}

// New locates the EFI_STORAGE_SECURITY_COMMAND_PROTOCOL and returns a transport
// over it. It fails closed if the protocol is absent (no SED, or firmware without
// Storage Security support), so the caller never proceeds without a real carrier.
//
// Limitation: it uses the first protocol instance (go-boot exposes LocateProtocol,
// not LocateHandleBuffer) with MediaId 0. That is sufficient for the single-device
// EDK2 MockOpalDxe (Phase 6); selecting among multiple drives and deriving the real
// MediaId from EFI_BLOCK_IO is a real-hardware refinement (Phase 8) needing further
// go-boot fork additions (see ADR-0008).
func New() (*UEFI, error) {
	ssc, err := x64.UEFI.Boot.GetStorageSecurity()
	if err != nil {
		return nil, fmt.Errorf("transport: locate storage security protocol: %w", err)
	}
	return &UEFI{ssc: ssc, mediaID: 0, timeout: defaultTimeout}, nil
}

// Send issues an IF-SEND for the given security protocol and ComID.
func (u *UEFI) Send(proto uint8, comID uint16, data []byte) error {
	if err := u.ssc.SendData(u.mediaID, u.timeout, proto, comID, data); err != nil {
		return fmt.Errorf("transport: IF-SEND proto=%#x comID=%#x: %w", proto, comID, err)
	}
	return nil
}

// Recv issues an IF-RECV and returns up to size bytes.
func (u *UEFI) Recv(proto uint8, comID uint16, size int) ([]byte, error) {
	data, err := u.ssc.ReceiveData(u.mediaID, u.timeout, proto, comID, size)
	if err != nil {
		return nil, fmt.Errorf("transport: IF-RECV proto=%#x comID=%#x: %w", proto, comID, err)
	}
	return data, nil
}
