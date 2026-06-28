//go:build tamago && amd64

package transport

import (
	"errors"
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

// NewAll locates every EFI_STORAGE_SECURITY_COMMAND_PROTOCOL handle and returns a
// transport over each. It fails closed if the protocol is absent (no SED, or
// firmware without Storage Security support), so the caller never proceeds without
// a real carrier.
//
// A multi-NVMe system exposes one Storage Security handle per drive — most of them
// non-Opal disks that reject TCG commands (EFI_DEVICE_ERROR). Picking the right
// device is therefore the caller's job (a Level-0 Discovery probe selects the Opal
// SED; that is Opal protocol logic and must not live in the transport layer). This
// only enumerates carriers. MediaId 0 is used: firmware does not require a derived
// MediaId for these commands (confirmed on hardware — the SED answers Discovery
// with MediaId 0).
func NewAll() ([]*UEFI, error) {
	handles, err := x64.UEFI.Boot.LocateStorageSecurityHandles()
	if err != nil {
		return nil, fmt.Errorf("transport: locate storage security handles: %w", err)
	}

	ts := make([]*UEFI, 0, len(handles))
	for _, h := range handles {
		ssc, err := x64.UEFI.Boot.GetStorageSecurityByHandle(h)
		if err != nil {
			continue // a handle whose protocol cannot be resolved is not a usable carrier
		}
		ts = append(ts, &UEFI{ssc: ssc, mediaID: 0, timeout: defaultTimeout})
	}
	if len(ts) == 0 {
		return nil, errors.New("transport: no usable storage security device found")
	}
	return ts, nil
}

// swapComID byte-swaps a TCG ComID into the EFI_STORAGE_SECURITY_COMMAND_PROTOCOL
// SecurityProtocolSpecificData field. Firmware writes that UINT16 into the SECURITY
// PROTOCOL command's SP-Specific field in the opposite byte order to TCG's on-wire
// ComID, so the logical ComID must be swapped here. Confirmed on hardware: Level-0
// Discovery (ComID 0x0001) returns data only when passed as 0x0100; a real-drive
// query with the unswapped value succeeds but yields a zero-filled buffer. The EDK2
// MockOpalDxe driver mirrors this (it swaps back); the host MockTPer bypasses this
// transport entirely, so it is unaffected.
func swapComID(comID uint16) uint16 { return comID<<8 | comID>>8 }

// Send issues an IF-SEND for the given security protocol and ComID. Per the
// opal.Transport retention contract, it makes no Go-side copy of data and does
// not retain it: the caller's buffer is handed to the firmware call directly
// (firmware/DMA-side copies are beyond zeroization reach; see opal.Transport).
func (u *UEFI) Send(proto uint8, comID uint16, data []byte) error {
	if err := u.ssc.SendData(u.mediaID, u.timeout, proto, swapComID(comID), data); err != nil {
		return fmt.Errorf("transport: IF-SEND proto=%#x comID=%#x: %w", proto, comID, err)
	}
	return nil
}

// Recv issues an IF-RECV and returns up to size bytes.
func (u *UEFI) Recv(proto uint8, comID uint16, size int) ([]byte, error) {
	data, err := u.ssc.ReceiveData(u.mediaID, u.timeout, proto, swapComID(comID), size)
	if err != nil {
		return nil, fmt.Errorf("transport: IF-RECV proto=%#x comID=%#x: %w", proto, comID, err)
	}
	return data, nil
}
