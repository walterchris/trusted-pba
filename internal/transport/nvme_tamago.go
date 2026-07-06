//go:build tamago && amd64

package transport

import (
	"errors"
	"fmt"

	"github.com/walterchris/go-boot/uefi/x64"
)

// NVMe carries Opal IF-SEND/IF-RECV over the firmware
// EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL (NVMe Security Send/Receive admin commands).
// Unlike the Storage-Security carrier it is not mediated by a firmware TCG stack,
// and it additionally exposes the drive serial (credential.Serialer) for the
// sedutil-pbkdf2 salt.
type NVMe struct {
	npt nvmePassThru
}

// nvmePassThru is the slice of go-boot's protocol the transport uses (defined for
// testability/clarity; satisfied by *uefi.NVMePassThru).
type nvmePassThru interface {
	SecuritySend(securityProtocol uint8, comID uint16, payload []byte) error
	SecurityReceive(securityProtocol uint8, comID uint16, size int) ([]byte, error)
	SerialNumber() ([]byte, error)
}

// NewAllNVMe locates every EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL handle and returns a
// transport over each. It fails closed if the protocol is absent (no NVMe
// controller, or firmware without NVMe pass-thru support), so the caller never
// proceeds without a real carrier.
//
// A multi-NVMe system exposes one pass-thru handle per drive — most of them
// non-Opal disks that reject TCG commands. Picking the right device is therefore
// the caller's job (a Level-0 Discovery probe selects the Opal SED; that is Opal
// protocol logic and must not live in the transport layer). This only enumerates
// carriers.
func NewAllNVMe() ([]*NVMe, error) {
	handles, err := x64.UEFI.Boot.LocateNVMePassThruHandles()
	if err != nil {
		return nil, fmt.Errorf("transport: locate NVMe pass-thru handles: %w", err)
	}

	ts := make([]*NVMe, 0, len(handles))
	for _, h := range handles {
		npt, err := x64.UEFI.Boot.GetNVMePassThruByHandle(h)
		if err != nil {
			continue // a handle whose protocol cannot be resolved is not a usable carrier
		}
		ts = append(ts, &NVMe{npt: npt})
	}
	if len(ts) == 0 {
		return nil, errors.New("transport: no usable NVMe pass-thru device found")
	}
	return ts, nil
}

// Send issues an NVMe Security Send (IF-SEND) for the given security protocol and
// ComID. Per the opal.Transport retention contract, it makes no Go-side copy of
// data and does not retain it: the caller's buffer is handed to the firmware call
// directly (firmware/DMA-side copies are beyond zeroization reach; see
// opal.Transport).
//
// NO ComID byte-swap: NVMe carries the TCG ComID in its native (SP-Specific) order.
// The swap the Storage-Security carrier performs is a property of
// EFI_STORAGE_SECURITY_COMMAND_PROTOCOL's marshalling, not of NVMe — do NOT add one
// here.
func (n *NVMe) Send(proto uint8, comID uint16, data []byte) error {
	if err := n.npt.SecuritySend(proto, comID, data); err != nil {
		return fmt.Errorf("transport: NVMe IF-SEND proto=%#x comID=%#x: %w", proto, comID, err)
	}
	return nil
}

// Recv issues an NVMe Security Receive (IF-RECV) and returns up to size bytes.
//
// NO ComID byte-swap: see Send — NVMe passes the ComID in native order.
func (n *NVMe) Recv(proto uint8, comID uint16, size int) ([]byte, error) {
	data, err := n.npt.SecurityReceive(proto, comID, size)
	if err != nil {
		return nil, fmt.Errorf("transport: NVMe IF-RECV proto=%#x comID=%#x: %w", proto, comID, err)
	}
	return data, nil
}

// Serial returns the drive's raw 20-byte serial number as-is (space-padded ASCII
// as the drive reports it), for use as the sedutil-pbkdf2 PBKDF2 salt. It is
// read-only and touches no credential (credential.Serialer).
func (n *NVMe) Serial() ([]byte, error) {
	sn, err := n.npt.SerialNumber()
	if err != nil {
		return nil, fmt.Errorf("transport: NVMe serial number: %w", err)
	}
	return sn, nil
}
