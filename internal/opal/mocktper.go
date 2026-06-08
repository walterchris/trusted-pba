package opal

import (
	"bytes"
	"errors"
	"fmt"
)

// MockTPer is a native fake Opal drive (TPer) implementing Transport. It speaks the
// real TCG wire format — it decodes the packets/methods the Client sends and emits
// real Discovery0 / SyncSession / method-result streams — so it exercises the full
// byte-faithful protocol without UEFI or hardware. It lives in this package because
// it shares the (unexported) codec; the thin real transports (UEFI, hardware) live
// in internal/transport. See ADR-0004.
//
// Not safe for concurrent use.
type MockTPer struct {
	// Configuration (set before use).
	PIN              []byte // the correct Admin1 credential
	LockingSupported bool

	// Device state.
	baseComID  uint16
	locked     bool
	mbrEnabled bool
	mbrDone    bool

	// Session state.
	tsn, hsn uint32

	fault Fault
	resp  []byte // pending session response for the next Recv
}

// Fault selects an injected transport failure for negative tests.
type Fault int

const (
	// FaultNone is normal operation.
	FaultNone Fault = iota
	// FaultTimeout makes every Send/Recv time out.
	FaultTimeout
	// FaultMalformed makes session Recv return undecodable bytes.
	FaultMalformed
)

// ErrTimeout is returned by an injected transport timeout.
var ErrTimeout = errors.New("opal: transport timeout")

// NewMockTPer returns a locked Opal drive with a shadow MBR enabled and the given
// Admin1 credential.
func NewMockTPer(pin []byte) *MockTPer {
	return &MockTPer{
		PIN:              pin,
		LockingSupported: true,
		baseComID:        0x07fe,
		locked:           true,
		mbrEnabled:       true,
		mbrDone:          false,
	}
}

// Inject sets a transport fault (FaultNone clears it).
func (m *MockTPer) Inject(f Fault) { m.fault = f }

// Locked reports the current global-range lock state.
func (m *MockTPer) Locked() bool { return m.locked }

// MBRDone reports whether the shadow MBR has been marked done.
func (m *MockTPer) MBRDone() bool { return m.mbrDone }

// Send implements Transport.
func (m *MockTPer) Send(proto uint8, comID uint16, data []byte) error {
	if m.fault == FaultTimeout {
		return ErrTimeout
	}
	if proto != protoSecurity || comID != m.baseComID {
		return fmt.Errorf("opal: mock: unexpected IF-SEND proto=%d comID=0x%04x", proto, comID)
	}
	payload, err := decodePacket(data)
	if err != nil {
		return err
	}
	m.resp = m.handle(payload)
	return nil
}

// Recv implements Transport.
func (m *MockTPer) Recv(proto uint8, comID uint16, size int) ([]byte, error) {
	if m.fault == FaultTimeout {
		return nil, ErrTimeout
	}
	if proto != protoSecurity {
		return nil, fmt.Errorf("opal: mock: unexpected IF-RECV proto=%d", proto)
	}
	var out []byte
	switch {
	case comID == comIDDiscovery:
		out = buildDiscovery(m.discovery())
	case comID != m.baseComID:
		return nil, fmt.Errorf("opal: mock: unexpected IF-RECV comID=0x%04x", comID)
	case m.fault == FaultMalformed:
		out = []byte{0xde, 0xad, 0xbe, 0xef}
	default:
		out = m.resp
	}
	// A real IF-RECV returns at most the requested transfer length.
	if size >= 0 && size < len(out) {
		out = out[:size]
	}
	return out, nil
}

func (m *MockTPer) discovery() *Discovery {
	return &Discovery{
		OpalSSC:          true,
		BaseComID:        m.baseComID,
		LockingSupported: m.LockingSupported,
		LockingEnabled:   true,
		Locked:           m.locked,
		MBREnabled:       m.mbrEnabled,
		MBRDone:          m.mbrDone,
	}
}

// handle interprets one session method payload and returns the packet-framed
// response. Unparseable or unauthorized requests yield a non-success status so the
// client fails closed.
func (m *MockTPer) handle(payload []byte) []byte {
	if bytes.Equal(payload, []byte{tokEndOfSession}) {
		m.tsn, m.hsn = 0, 0
		return m.frame([]byte{tokEndOfSession})
	}
	toks, err := tokenize(payload)
	if err != nil || len(toks) < 3 || !toks[0].isControl(tokCall) || !toks[1].isBytes || !toks[2].isBytes {
		return m.frame(resultStream(statusNotAuthorized))
	}
	method := UID(toks[2].data)
	switch method {
	case uidMethodStartSession:
		return m.frame(m.startSession(toks))
	case uidMethodSet:
		return m.frame(m.setMethod(toks))
	default:
		return m.frame(resultStream(statusNotAuthorized))
	}
}

func (m *MockTPer) frame(payload []byte) []byte {
	return encodePacket(m.baseComID, m.tsn, m.hsn, payload)
}

// startSession validates the credential and, on success, opens a session and
// returns a SyncSession result; otherwise a NOT_AUTHORIZED result.
func (m *MockTPer) startSession(toks []token) []byte {
	hsn, _, auth, pin, ok := parseStartSession(toks)
	if !ok {
		return resultStream(statusNotAuthorized)
	}
	// Only Admin1 is provisioned in this mock; the credential must match.
	if auth != uidAuthAdmin1 || !bytes.Equal(pin, m.PIN) {
		return syncSessionStream(statusAuthLockedOut, hsn, 0)
	}
	m.hsn = hsn
	m.tsn = 0x1000
	return syncSessionStream(statusSuccess, m.hsn, m.tsn)
}

// setMethod applies a Set to the global range or MBRControl within an open session.
func (m *MockTPer) setMethod(toks []token) []byte {
	if m.tsn == 0 { // no authenticated session
		return resultStream(statusNotAuthorized)
	}
	invoker, cols, ok := parseSet(toks)
	if !ok {
		return resultStream(statusNotAuthorized)
	}
	switch invoker {
	case uidGlobalRange:
		for _, c := range cols {
			if (c.num == colReadLocked || c.num == colWriteLocked) && c.val == 0 {
				m.locked = false
			}
		}
	case uidMBRControl:
		for _, c := range cols {
			if c.num == colMBRDone && c.val == 1 {
				m.mbrDone = true
			}
		}
	default:
		return resultStream(statusNotAuthorized)
	}
	return resultStream(statusSuccess)
}

// resultStream builds a method result with empty results: StartList EndList
// EndOfData StartList <status> 0 0 EndList.
func resultStream(status uint64) []byte {
	var b builder
	b.control(tokStartList)
	b.control(tokEndList)
	b.control(tokEndOfData)
	b.control(tokStartList)
	b.uint(status)
	b.uint(0)
	b.uint(0)
	b.control(tokEndList)
	return b.buf
}

// syncSessionStream builds a SyncSession result: Call SMUID SyncSession StartList
// HSN TSN EndList EndOfData StartList <status> 0 0 EndList.
func syncSessionStream(status uint64, hsn, tsn uint32) []byte {
	var b builder
	b.control(tokCall)
	b.uid(uidSMUID)
	b.uid(uidMethodSyncSession)
	b.control(tokStartList)
	b.uint(uint64(hsn))
	b.uint(uint64(tsn))
	b.control(tokEndList)
	b.control(tokEndOfData)
	b.control(tokStartList)
	b.uint(status)
	b.uint(0)
	b.uint(0)
	b.control(tokEndList)
	return b.buf
}

// parseStartSession extracts the host session id, SP, authority, and challenge from
// a StartSession token stream.
func parseStartSession(toks []token) (hsn uint32, spID, auth UID, pin []byte, ok bool) {
	// Call SMUID StartSession StartList HSN SPID write [StartName name val EndName]...
	if len(toks) < 7 || !toks[3].isControl(tokStartList) || !toks[4].isInt || !toks[5].isBytes {
		return 0, UID{}, UID{}, nil, false
	}
	hsn = u32(toks[4].u)
	spID = UID(toks[5].data)
	for i := 7; i+3 < len(toks); {
		if !toks[i].isControl(tokStartName) {
			break
		}
		name := toks[i+1]
		val := toks[i+2]
		if !name.isInt || !toks[i+3].isControl(tokEndName) {
			return 0, UID{}, UID{}, nil, false
		}
		switch name.u {
		case 0:
			if val.isBytes {
				pin = val.data
			}
		case 3:
			if val.isBytes && len(val.data) == 8 {
				auth = UID(val.data)
			}
		}
		i += 4
	}
	return hsn, spID, auth, pin, true
}

// parseSet extracts the invoking object and the written columns from a Set stream.
func parseSet(toks []token) (invoker UID, cols []column, ok bool) {
	if len(toks) < 8 || !toks[1].isBytes {
		return UID{}, nil, false
	}
	invoker = UID(toks[1].data)
	// Walk for StartName <col:int> <val:int> EndName tuples. The outer "Values"
	// name is skipped automatically: its value is a list (StartList), not an int.
	for i := 0; i+3 < len(toks); i++ {
		if toks[i].isControl(tokStartName) && toks[i+1].isInt && toks[i+2].isInt && toks[i+3].isControl(tokEndName) {
			cols = append(cols, column{toks[i+1].u, toks[i+2].u})
		}
	}
	return invoker, cols, true
}
