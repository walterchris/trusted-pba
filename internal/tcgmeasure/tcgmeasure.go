// Package tcgmeasure builds TCG measured-boot events for the pba-override path and
// extends them into a TPM PCR through an abstract Extender (the UEFI
// EFI_TCG2_PROTOCOL in production, a fake in tests). It is pure Go — no UEFI — so
// the exact event byte layout is host-testable, mirroring the Opal/TCGTransport
// split (ADR-0015).
package tcgmeasure

import (
	"encoding/binary"
	"strings"
)

// evEFIVariableAuthority is EV_EFI_VARIABLE_AUTHORITY (TCG PC Client Platform
// Firmware Profile) — the event type firmware and SHIM use in PCR 7 to record which
// authority validated an image.
const evEFIVariableAuthority = 0x800000E0

// pcrSecureBootAuthority is PCR 7, the Secure Boot policy/authority register.
const pcrSecureBootAuthority = 7

// overrideAuthorityName is the UEFI_VARIABLE_DATA UnicodeName marking this as the
// PBA override authority (analogous to SHIM's "MokList"). ASCII by construction.
const overrideAuthorityName = "PbaOverride"

// pbaNamespaceGUID identifies the PBA as the authorizing agent; it is used as both
// the UEFI_VARIABLE_DATA VendorGuid and the EFI_SIGNATURE_DATA SignatureOwner. It is
// deliberately NEITHER the firmware db GUID nor Microsoft's owner GUID: the event
// attests that the *PBA* (not firmware db) authorized the image, which is the honest
// record on an our-keys-only platform (ADR-0015). Stored in EFI mixed-endian wire
// form.
var pbaNamespaceGUID = efiGUID(0x2f7e5a3c, 0x9b41, 0x4d8e, [8]byte{0xa2, 0x6c, 0x11, 0x0d, 0x0f, 0xb5, 0x0a, 0xe0})

// Extender extends a hashed event into a TPM PCR and appends it to the TCG event
// log. It abstracts EFI_TCG2_PROTOCOL.HashLogExtendEvent; go-boot's *uefi.TCG2
// satisfies it directly.
type Extender interface {
	HashLogExtendEvent(flags uint64, pcrIndex uint32, eventType uint32, data []byte) error
}

// MeasureOverrideAuthority extends PCR 7 with an EV_EFI_VARIABLE_AUTHORITY event
// recording that the PBA authorized an override image using caDER — the db CA
// certificate the image's signer chained to. The event is deterministic for fixed
// inputs, so it is a one-time reseal event and BitLocker-safe (ADR-0015).
func MeasureOverrideAuthority(e Extender, caDER []byte) error {
	ev := authorityEvent(caDER)
	return e.HashLogExtendEvent(0, pcrSecureBootAuthority, evEFIVariableAuthority, ev)
}

// Fatal reports whether a measurement failure must abort the boot: only when the
// policy requires measured boot (require_tpm). With require_tpm false the override
// proceeds best-effort (the caller logs the failure). A nil err is never fatal. This
// is the pba-override measurement fail-closed rule (ADR-0015/0016), factored out so
// it is host-testable.
func Fatal(requireTPM bool, err error) bool { return requireTPM && err != nil }

// authorityEvent builds the UEFI_VARIABLE_DATA body of the PBA's
// EV_EFI_VARIABLE_AUTHORITY event: { EFI_GUID VariableName; UINT64 UnicodeNameLength;
// UINT64 VariableDataLength; CHAR16 UnicodeName[]; UINT8 VariableData[] }, where
// VariableData is EFI_SIGNATURE_DATA { EFI_GUID SignatureOwner; UINT8 SignatureData[] }.
// The VariableName GUID/name and the SignatureOwner are the fixed PBA namespace
// (ADR-0015); only sigData (the authorizing CA DER) varies. UnicodeNameLength counts
// CHAR16, VariableDataLength counts bytes.
func authorityEvent(sigData []byte) []byte {
	name16 := utf16le(overrideAuthorityName)
	varData := make([]byte, 0, 16+len(sigData))
	varData = append(varData, pbaNamespaceGUID[:]...)
	varData = append(varData, sigData...)

	buf := make([]byte, 0, 16+8+8+len(name16)+len(varData))
	buf = append(buf, pbaNamespaceGUID[:]...)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(name16)/2)) // UnicodeNameLength (CHAR16 count)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(varData)))  // VariableDataLength (bytes)
	buf = append(buf, name16...)
	buf = append(buf, varData...)
	return buf
}

// efiGUID assembles the 16-byte EFI mixed-endian GUID wire form: Data1 (uint32 LE),
// Data2/Data3 (uint16 LE), Data4 (8 bytes as-is).
func efiGUID(d1 uint32, d2, d3 uint16, d4 [8]byte) [16]byte {
	var g [16]byte
	binary.LittleEndian.PutUint32(g[0:], d1)
	binary.LittleEndian.PutUint16(g[4:], d2)
	binary.LittleEndian.PutUint16(g[6:], d3)
	copy(g[8:], d4[:])
	return g
}

// utf16le encodes an ASCII string as UTF-16LE (one CHAR16 per byte). The only
// caller passes a compile-time ASCII constant.
func utf16le(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		b = append(b, s[i], 0)
	}
	return b
}

// --- Override boot-application measurement: the override loads the next image via
// LoadImageBuffer (a memory SourceBuffer), which firmware does not measure into PCR 4.
// This restores that measurement — extending the image's Authenticode hash into the
// configured PCR(s) as an EV_EFI_BOOT_SERVICES_APPLICATION event, exactly as a firmware
// device-path load would — so a chained bootmgfw/UKI is represented in the measured
// boot (and BitLocker's PCR-4 seal reproduces). ---

const (
	evEFIBootServicesApp = 0x80000003 // EV_EFI_BOOT_SERVICES_APPLICATION
	peCoffImageFlag      = 0x10       // EFI_TCG2_PE_COFF_IMAGE
)

// ImageExtender extends a PE/COFF image measurement (via EFI_TCG2_PE_COFF_IMAGE) into a
// PCR and logs it. go-boot's *uefi.TCG2 satisfies it.
type ImageExtender interface {
	HashLogExtendEventEx(flags uint64, pcrIndex uint32, eventType uint32, dataToHash, eventBody []byte) error
}

// MeasureImage extends the Authenticode hash of a PE/COFF image into each PCR in pcrs
// as an EV_EFI_BOOT_SERVICES_APPLICATION event, mimicking a firmware device-path load.
// espPath is the image's ESP-relative path (recorded in the log's device path); locInMem
// is the image buffer's physical address. It stops at the first extend error.
func MeasureImage(e ImageExtender, image []byte, espPath string, locInMem uint64, pcrs []uint32) error {
	body := imageLoadEvent(locInMem, uint64(len(image)), 0, deviceFilePath(espPath))
	for _, pcr := range pcrs {
		if err := e.HashLogExtendEventEx(peCoffImageFlag, pcr, evEFIBootServicesApp, image, body); err != nil {
			return err
		}
	}
	return nil
}

// imageLoadEvent builds a UEFI_IMAGE_LOAD_EVENT: ImageLocationInMemory,
// ImageLengthInMemory, ImageLinkTimeAddress, LengthOfDevicePath, DevicePath.
func imageLoadEvent(locInMem, lenInMem, linkTime uint64, devicePath []byte) []byte {
	b := make([]byte, 0, 32+len(devicePath))
	b = binary.LittleEndian.AppendUint64(b, locInMem)
	b = binary.LittleEndian.AppendUint64(b, lenInMem)
	b = binary.LittleEndian.AppendUint64(b, linkTime)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(devicePath)))
	return append(b, devicePath...)
}

// deviceFilePath builds a UEFI device path (a MEDIA/FILEPATH node + End node) from an
// ESP-relative path like "EFI/MICROSOFT/BOOT/BOOTMGFW.EFI", normalizing separators to
// backslash with a leading backslash.
func deviceFilePath(espPath string) []byte {
	p := "\\" + strings.ReplaceAll(strings.TrimLeft(espPath, `/\`), "/", `\`)
	name := utf16le(p)
	name = append(name, 0, 0) // CHAR16 null terminator
	node := make([]byte, 4+len(name))
	node[0] = 0x04 // MEDIA_DEVICE_PATH
	node[1] = 0x04 // MEDIA_FILEPATH_DP
	// Node length is 4 + a compiled-in policy ESP path in UTF-16 — a few dozen bytes,
	// far below the uint16 max; the source is the signed, compiled-in policy, not
	// runtime input.
	binary.LittleEndian.PutUint16(node[2:], uint16(4+len(name))) //nolint:gosec // bounded by the compiled-in policy path
	copy(node[4:], name)
	end := []byte{0x7F, 0xFF, 0x04, 0x00} // END_ENTIRE_DEVICE_PATH
	return append(node, end...)
}
