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
//
// Before resolving the carriers it resets each NVMe controller (#79): the firmware
// leaves the SED's TCG stack in its POST-time state, in which Level-0 Discovery
// reports a stale base ComID and StartSession is rejected (method status 0x0c).
// Re-binding the firmware NVMe driver re-runs controller initialisation (the CC.EN
// disable/enable the OS driver also performs), which resets the TCG stack to its
// base ComID so a session can be opened — mirroring why the OS path works.
func NewAllNVMe() ([]*NVMeUEFI, error) {
	handles, err := x64.UEFI.Boot.LocateNVMePassThruHandles()
	if err != nil {
		return nil, fmt.Errorf("transport: locate nvme passthru handles: %w", err)
	}

	// Reset each controller, then re-locate: DisconnectController uninstalls the
	// PassThru protocol, so the pre-reset handles are stale afterwards. Best effort
	// — a controller that will not reset still fails closed at StartSession.
	dbg("NVMe controllers: %d", len(handles))
	for _, h := range handles {
		resetNVMeController(h)
	}
	handles, err = x64.UEFI.Boot.LocateNVMePassThruHandles()
	if err != nil {
		return nil, fmt.Errorf("transport: re-locate nvme passthru handles after reset: %w", err)
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

// resetNVMeController re-initialises one NVMe controller by unbinding then
// rebinding its firmware driver (DisconnectController + recursive
// ConnectController), which re-runs the controller's CC.EN reset sequence.
func resetNVMeController(handle uint64) {
	dErr := x64.UEFI.Boot.DisconnectController(handle, 0, 0)
	cErr := x64.UEFI.Boot.ConnectController(handle, 0, 0, true)
	dbg("reset controller %#x: disconnect=%v connect=%v", handle, dErr, cErr)
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
