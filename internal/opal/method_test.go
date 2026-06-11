package opal

import (
	"errors"
	"testing"
)

// TestMockParsersRejectShortUID covers F-L1: the mock's request parsers convert
// byte-string atoms to UID ([8]byte) guarding only isBytes, so a shorter atom
// panicked. Each parser must fail closed (ok == false), not panic, on a non-8-byte
// UID. The parsers are tested directly because parseSet is only reachable after a
// session is open (the fuzzer, starting at tsn == 0, never reaches it).
func TestMockParsersRejectShortUID(t *testing.T) {
	shortUID := func() token { return token{isBytes: true, data: []byte{0x01, 0x02, 0x03}} }
	startName := token{ctrl: tokStartName}
	endName := token{ctrl: tokEndName}
	startList := token{ctrl: tokStartList}
	intTok := func(u uint64) token { return token{isInt: true, u: u} }

	t.Run("handle short method uid", func(t *testing.T) {
		// Call + invoker(8) + short method UID: panicked at UID(toks[2]).
		payload := append([]byte{tokCall}, byte(0xA0|8))
		payload = append(payload, uidSMUID[:]...)
		payload = append(payload, byte(0xA0|3), 0x01, 0x02, 0x03) // 3-byte method atom
		if got := NewMockTPer([]byte("pw")).handle(payload); len(got) == 0 {
			t.Error("handle returned no frame")
		}
	})

	t.Run("parseStartSession short spid", func(t *testing.T) {
		// >= 7 tokens so the len(toks) < 7 guard passes and the toks[5] UID
		// conversion is actually reached (toks[6] is the "write" flag).
		toks := []token{
			{ctrl: tokCall}, {isBytes: true, data: uidSMUID[:]}, {isBytes: true, data: uidMethodStartSession[:]},
			startList, intTok(1), shortUID(), intTok(1), // HSN, short SPID at toks[5], write
		}
		if _, _, _, _, ok := parseStartSession(toks); ok {
			t.Error("parseStartSession accepted a short SPID UID")
		}
	})

	t.Run("parseSet short invoker", func(t *testing.T) {
		toks := []token{
			{ctrl: tokCall}, shortUID(), {isBytes: true, data: uidMethodSet[:]}, // short invoker at toks[1]
			startList, startName, intTok(1), intTok(0), endName,
		}
		if _, _, ok := parseSet(toks); ok {
			t.Error("parseSet accepted a short invoker UID")
		}
	})
}

// TestSyncSessionIDsRejectsOversizeID covers F-L2: session ids are device-supplied
// token integers spanning a full uint64; narrowing with u32 silently truncated
// them, so a TPer echoing HSN 0x1_0000_0001 would pass the host-session-id match.
// They must be rejected, not truncated.
func TestSyncSessionIDsRejectsOversizeID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hsn, tsn uint64
	}{
		{"oversize hsn", 0x1_0000_0001, 0x1000},
		{"oversize tsn", 1, 0x1_0000_1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := syncSessionStream64(statusSuccess, tc.hsn, tc.tsn)
			if _, _, err := syncSessionIDs(stream); !errors.Is(err, ErrMethod) {
				t.Fatalf("want ErrMethod for a >32-bit session id, got %v", err)
			}
		})
	}
}

// syncSessionStream64 is syncSessionStream without the uint32 narrowing, so a test
// can emit the out-of-range session ids a real device could send.
func syncSessionStream64(status, hsn, tsn uint64) []byte {
	var b builder
	b.control(tokCall)
	b.uid(uidSMUID)
	b.uid(uidMethodSyncSession)
	b.control(tokStartList)
	b.uint(hsn)
	b.uint(tsn)
	b.control(tokEndList)
	b.control(tokEndOfData)
	b.control(tokStartList)
	b.uint(status)
	b.uint(0)
	b.uint(0)
	b.control(tokEndList)
	return b.buf
}
