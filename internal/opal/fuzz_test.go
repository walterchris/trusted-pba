package opal

import "testing"

// FuzzResponseParse exercises the device-response parsing path with arbitrary bytes
// (the bytes a malicious or malfunctioning drive could return). Per the compliance
// baseline §12, the TCG response parsers must never panic — they must fail closed.
func FuzzResponseParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xF8, 0xF0, 0xF1, 0xF9})
	f.Add(buildDiscovery(&Discovery{OpalSSC: true, BaseComID: 0x07fe, LockingSupported: true}))
	f.Add(encodePacket(0x07fe, 0x1000, 1, syncSessionStream(statusSuccess, 1, 0x1000)))

	f.Fuzz(func(_ *testing.T, data []byte) {
		// None of these may panic on attacker-controlled input.
		_, _ = tokenize(data)
		_, _ = parseDiscovery(data)
		if payload, err := decodePacket(data); err == nil {
			_, _ = methodStatus(payload)
			_, _, _ = syncSessionIDs(payload)
		}
	})
}
