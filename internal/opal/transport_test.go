package opal

import (
	"bytes"
	"errors"
	"testing"
)

func TestPacketRoundTrip(t *testing.T) {
	payload := []byte{tokCall, 0x01, 0x02, 0x03} // 4 bytes (already aligned)
	frame := encodePacket(0x07fe, 0x1000, 1, payload)
	got, err := decodePacket(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %x want %x", got, payload)
	}

	// Unaligned payload must round-trip too (encoder pads, decoder uses subLen).
	odd := []byte{0xF0, 0xF1, 0xF9} // 3 bytes
	if got, err := decodePacket(encodePacket(0x07fe, 0, 0, odd)); err != nil || !bytes.Equal(got, odd) {
		t.Fatalf("odd payload: got %x err %v", got, err)
	}
}

func TestDecodePacketFailsClosed(t *testing.T) {
	cases := map[string][]byte{
		"short frame":     make([]byte, 10),
		"comLen overruns": func() []byte { b := encodePacket(1, 0, 0, []byte{0xff}); b[19] = 0xff; return b }(),
		"subLen overruns": func() []byte { b := encodePacket(1, 0, 0, []byte{0xff}); b[55] = 0xff; return b }(),
	}
	for name, in := range cases {
		if _, err := decodePacket(in); !errors.Is(err, ErrPacket) {
			t.Errorf("%s: want ErrPacket, got %v", name, err)
		}
	}
}

func TestMockRejectsInvalidComID(t *testing.T) {
	dev := NewMockTPer([]byte("pw"))
	good := encodePacket(0x07fe, 0, 0, []byte{tokEndOfSession})
	if err := dev.Send(protoSecurity, 0x1234, good); err == nil {
		t.Error("Send to wrong ComID must error")
	}
	if _, err := dev.Recv(protoSecurity, 0x1234, recvBufSize); err == nil {
		t.Error("Recv from wrong ComID must error")
	}
	if _, err := dev.Recv(0x02, comIDDiscovery, recvBufSize); err == nil {
		t.Error("Recv with wrong security protocol must error")
	}
}
