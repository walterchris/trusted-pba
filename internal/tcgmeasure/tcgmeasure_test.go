package tcgmeasure

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// fakeExtender captures the single HashLogExtendEvent call.
type fakeExtender struct {
	flags    uint64
	pcr      uint32
	evType   uint32
	data     []byte
	called   int
	failWith error
}

func (f *fakeExtender) HashLogExtendEvent(flags uint64, pcr, evType uint32, data []byte) error {
	f.called++
	f.flags, f.pcr, f.evType = flags, pcr, evType
	f.data = append([]byte(nil), data...)
	return f.failWith
}

func TestMeasureOverrideAuthorityCall(t *testing.T) {
	ca := []byte{0xAA, 0xBB, 0xCC}
	f := &fakeExtender{}
	if err := MeasureOverrideAuthority(f, ca); err != nil {
		t.Fatalf("MeasureOverrideAuthority: %v", err)
	}
	if f.called != 1 {
		t.Fatalf("extender called %d times, want 1", f.called)
	}
	if f.flags != 0 {
		t.Errorf("flags = %#x, want 0 (measured+logged)", f.flags)
	}
	if f.pcr != 7 {
		t.Errorf("PCR = %d, want 7 (Secure Boot authority)", f.pcr)
	}
	if f.evType != 0x800000E0 {
		t.Errorf("eventType = %#x, want 0x800000E0 (EV_EFI_VARIABLE_AUTHORITY)", f.evType)
	}
}

// TestAuthorityEventLayout locks every field of the UEFI_VARIABLE_DATA at its exact
// offset, independent of the production concatenation.
func TestAuthorityEventLayout(t *testing.T) {
	ca := []byte{0x01, 0x02, 0x03, 0x04}
	ev := authorityEvent(ca)

	name16 := utf16le(overrideAuthorityName)
	wantLen := 16 + 8 + 8 + len(name16) + 16 + len(ca)
	if len(ev) != wantLen {
		t.Fatalf("event len = %d, want %d", len(ev), wantLen)
	}
	// VariableName GUID
	if !bytes.Equal(ev[0:16], pbaNamespaceGUID[:]) {
		t.Errorf("VariableName GUID = % x, want % x", ev[0:16], pbaNamespaceGUID[:])
	}
	// UnicodeNameLength = CHAR16 count = len("PbaOverride") = 11
	if got := binary.LittleEndian.Uint64(ev[16:24]); got != uint64(len(overrideAuthorityName)) {
		t.Errorf("UnicodeNameLength = %d, want %d", got, len(overrideAuthorityName))
	}
	// VariableDataLength = 16 (SignatureOwner) + len(ca)
	if got := binary.LittleEndian.Uint64(ev[24:32]); got != uint64(16+len(ca)) {
		t.Errorf("VariableDataLength = %d, want %d", got, 16+len(ca))
	}
	// UnicodeName (UTF-16LE)
	nameEnd := 32 + len(name16)
	if !bytes.Equal(ev[32:nameEnd], name16) {
		t.Errorf("UnicodeName = % x, want % x", ev[32:nameEnd], name16)
	}
	// VariableData = SignatureOwner GUID || CA DER
	if !bytes.Equal(ev[nameEnd:nameEnd+16], pbaNamespaceGUID[:]) {
		t.Errorf("SignatureOwner = % x, want % x", ev[nameEnd:nameEnd+16], pbaNamespaceGUID[:])
	}
	if !bytes.Equal(ev[nameEnd+16:], ca) {
		t.Errorf("SignatureData = % x, want % x", ev[nameEnd+16:], ca)
	}
}

// TestDeterministic — same inputs must produce byte-identical events (the property
// that keeps PCR 7 reproducible / BitLocker-safe, ADR-0015).
func TestDeterministic(t *testing.T) {
	ca := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	a := authorityEvent(ca)
	b := authorityEvent(ca)
	if !bytes.Equal(a, b) {
		t.Fatalf("event not deterministic:\n a=% x\n b=% x", a, b)
	}
}

// TestExtendFailurePropagates — a failed extend must surface (the override then
// fails closed, ADR-0015 decision 3).
func TestExtendFailurePropagates(t *testing.T) {
	sentinel := errors.New("tpm busy")
	f := &fakeExtender{failWith: sentinel}
	if err := MeasureOverrideAuthority(f, []byte{0x00}); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want %v", err, sentinel)
	}
}

// imageCall records one HashLogExtendEventEx invocation.
type imageCall struct {
	flags      uint64
	pcr, evTyp uint32
	dataToHash []byte
	eventBody  []byte
}

type fakeImageExtender struct {
	calls []imageCall
	fail  error
}

func (f *fakeImageExtender) HashLogExtendEventEx(flags uint64, pcr, evTyp uint32, dataToHash, eventBody []byte) error {
	f.calls = append(f.calls, imageCall{flags, pcr, evTyp, append([]byte(nil), dataToHash...), append([]byte(nil), eventBody...)})
	return f.fail
}

// TestMeasureImage — one PE_COFF_IMAGE extend of the image per PCR, and a correct
// UEFI_IMAGE_LOAD_EVENT body.
func TestMeasureImage(t *testing.T) {
	img := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	f := &fakeImageExtender{}
	if err := MeasureImage(f, img, "EFI/MICROSOFT/BOOT/BOOTMGFW.EFI", 0x1000, []uint32{4, 12}); err != nil {
		t.Fatalf("MeasureImage: %v", err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("extend calls = %d, want 2 (one per PCR)", len(f.calls))
	}
	for i, pcr := range []uint32{4, 12} {
		c := f.calls[i]
		if c.flags != 0x10 {
			t.Errorf("call %d flags = %#x, want 0x10 (PE_COFF_IMAGE)", i, c.flags)
		}
		if c.pcr != pcr {
			t.Errorf("call %d PCR = %d, want %d", i, c.pcr, pcr)
		}
		if c.evTyp != 0x80000003 {
			t.Errorf("call %d eventType = %#x, want 0x80000003 (EV_EFI_BOOT_SERVICES_APPLICATION)", i, c.evTyp)
		}
		if !bytes.Equal(c.dataToHash, img) {
			t.Errorf("call %d dataToHash != image", i)
		}
	}
	// UEFI_IMAGE_LOAD_EVENT body: locInMem, lenInMem, linkTime, dpLen, dp
	body := f.calls[0].eventBody
	if got := binary.LittleEndian.Uint64(body[0:]); got != 0x1000 {
		t.Errorf("ImageLocationInMemory = %#x, want 0x1000", got)
	}
	if got := binary.LittleEndian.Uint64(body[8:]); got != uint64(len(img)) {
		t.Errorf("ImageLengthInMemory = %d, want %d", got, len(img))
	}
	wantDP := uint64(len(deviceFilePath("EFI/MICROSOFT/BOOT/BOOTMGFW.EFI")))
	if got := binary.LittleEndian.Uint64(body[24:]); got != wantDP {
		t.Errorf("LengthOfDevicePath = %d, want %d", got, wantDP)
	}
}

// TestMeasureImageStopsOnError — a failing extend aborts (fail closed at the caller).
func TestMeasureImageStopsOnError(t *testing.T) {
	f := &fakeImageExtender{fail: errors.New("tpm busy")}
	if err := MeasureImage(f, []byte{1}, "EFI/X.EFI", 0, []uint32{4, 12}); err == nil {
		t.Fatal("expected error")
	}
	if len(f.calls) != 1 {
		t.Errorf("calls = %d, want 1 (stopped after the first failure)", len(f.calls))
	}
}

// TestDeviceFilePath — MEDIA/FILEPATH node with backslash-normalized path + End node.
func TestDeviceFilePath(t *testing.T) {
	dp := deviceFilePath("EFI/MICROSOFT/BOOT/BOOTMGFW.EFI")
	if dp[0] != 0x04 || dp[1] != 0x04 {
		t.Fatalf("node type/subtype = %x %x, want 04 04 (MEDIA/FILEPATH)", dp[0], dp[1])
	}
	nodeLen := int(binary.LittleEndian.Uint16(dp[2:]))
	want := utf16le(`\EFI\MICROSOFT\BOOT\BOOTMGFW.EFI`)
	want = append(want, 0, 0) // null terminator
	if !bytes.Equal(dp[4:4+len(want)], want) {
		t.Errorf("path = % x, want % x", dp[4:4+len(want)], want)
	}
	end := dp[nodeLen:]
	if len(end) != 4 || end[0] != 0x7F || end[1] != 0xFF {
		t.Errorf("End node = % x, want 7F FF 04 00", end)
	}
	// leading separators are stripped before the single leading backslash is added
	if !bytes.Equal(deviceFilePath("/EFI/x"), deviceFilePath("EFI/x")) {
		t.Error("leading-separator normalization differs")
	}
}

// TestFatal — the pba-override measurement fail-closed rule (ADR-0015/0016): a
// measurement failure aborts the boot ONLY when the policy requires measured boot
// (require_tpm=true); otherwise it is tolerated (best-effort). This is the negative
// security case for the require_tpm gate.
func TestFatal(t *testing.T) {
	someErr := errors.New("no TCG2")
	if !Fatal(true, someErr) {
		t.Error("require_tpm=true + error must be fatal (fail closed)")
	}
	if Fatal(false, someErr) {
		t.Error("require_tpm=false + error must NOT be fatal (best-effort)")
	}
	if Fatal(true, nil) {
		t.Error("no error is never fatal")
	}
	if Fatal(false, nil) {
		t.Error("no error is never fatal")
	}
}

// TestNamespaceNotFirmwareOrMicrosoft — guard the honesty property: the PBA
// namespace must not be the firmware db GUID nor Microsoft's owner GUID (ADR-0015).
func TestNamespaceNotFirmwareOrMicrosoft(t *testing.T) {
	dbGUID := efiGUID(0xd719b2cb, 0x3d3a, 0x4596, [8]byte{0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f})
	msOwner := efiGUID(0x77fa9abd, 0x0359, 0x4d32, [8]byte{0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})
	if bytes.Equal(pbaNamespaceGUID[:], dbGUID[:]) {
		t.Error("PBA namespace GUID must not equal the firmware db GUID")
	}
	if bytes.Equal(pbaNamespaceGUID[:], msOwner[:]) {
		t.Error("PBA namespace GUID must not equal Microsoft's SignatureOwner GUID")
	}
}
