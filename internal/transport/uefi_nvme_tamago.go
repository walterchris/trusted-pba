//go:build tamago && amd64

package transport

import (
	"errors"
	"fmt"

	"github.com/walterchris/go-boot/uefi/x64"
)

// NVMeUEFI carries Opal IF-SEND/IF-RECV over the firmware
// EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL as raw NVMe Security Send/Receive admin
// commands. This bypasses EFI_STORAGE_SECURITY_COMMAND_PROTOCOL, which on the
// target firmware mediates the TCG ComID and refuses host StartSession (#79).
// Unlike the Storage Security carrier, the ComID needs no byte swap: the NVMe
// command Dword is built here in NVMe's native order.
type NVMeUEFI struct {
	pt nvmePassThru
}

// nvmePassThru is the slice of go-boot's protocol the transport uses (satisfied by
// *uefi.NVMePassThru).
type nvmePassThru interface {
	SecuritySend(securityProtocol uint8, comID uint16, payload []byte) error
	SecurityReceive(securityProtocol uint8, comID uint16, size int) ([]byte, error)
}

// NewAllNVMe locates every EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL handle (one per NVMe
// controller) and returns a transport over each. It fails closed if the protocol
// is absent. As with the Storage Security carriers, picking the Opal SED among
// several controllers is the caller's job (a Level-0 Discovery probe).
func NewAllNVMe() ([]*NVMeUEFI, error) {
	handles, err := x64.UEFI.Boot.LocateNVMePassThruHandles()
	if err != nil {
		return nil, fmt.Errorf("transport: locate nvme passthru handles: %w", err)
	}

	ts := make([]*NVMeUEFI, 0, len(handles))
	for _, h := range handles {
		pt, err := x64.UEFI.Boot.GetNVMePassThruByHandle(h)
		if err != nil {
			continue // a handle whose protocol cannot be resolved is not a usable carrier
		}
		ts = append(ts, &NVMeUEFI{pt: pt})
	}
	if len(ts) == 0 {
		return nil, errors.New("transport: no usable nvme passthru device found")
	}
	return ts, nil
}

// Send issues an IF-SEND (NVMe Security Send) for the given security protocol and
// ComID. Per the opal.Transport retention contract it makes no Go-side copy of
// data and does not retain it.
func (u *NVMeUEFI) Send(proto uint8, comID uint16, data []byte) error {
	if err := u.pt.SecuritySend(proto, comID, data); err != nil {
		return fmt.Errorf("transport: IF-SEND proto=%#x comID=%#x: %w", proto, comID, err)
	}
	return nil
}

// Recv issues an IF-RECV (NVMe Security Receive) and returns up to size bytes.
func (u *NVMeUEFI) Recv(proto uint8, comID uint16, size int) ([]byte, error) {
	data, err := u.pt.SecurityReceive(proto, comID, size)
	if err != nil {
		return nil, fmt.Errorf("transport: IF-RECV proto=%#x comID=%#x: %w", proto, comID, err)
	}
	return data, nil
}
