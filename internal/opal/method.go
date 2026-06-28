package opal

import (
	"errors"
	"fmt"
	"math"
)

// TCG method status codes (status list of a method result). 0 is success.
const (
	statusSuccess       = 0x00
	statusNotAuthorized = 0x01
	statusAuthLockedOut = 0x12
)

// ErrMethod is returned when a method result is malformed or carries a non-success
// status. Callers must fail closed.
var ErrMethod = errors.New("opal: method failed")

// ErrNotAuthorized is returned when the Authenticate method completes with a
// "false" result — the credential was rejected. Callers must fail closed.
var ErrNotAuthorized = errors.New("opal: not authorized")

// buildMethod assembles a TCG method invocation:
//
//	Call <invoker> <method> StartList <args> EndList EndOfData StartList 0 0 0 EndList
//
// args emits the positional/named argument tokens between the argument StartList
// and EndList. The trailing zero status list mirrors what a host sends (the TPer
// overwrites it in the response).
func buildMethod(invoker, method UID, args func(b *builder)) []byte {
	var b builder
	b.control(tokCall)
	b.uid(invoker)
	b.uid(method)
	b.control(tokStartList)
	if args != nil {
		args(&b)
	}
	b.control(tokEndList)
	b.control(tokEndOfData)
	b.control(tokStartList)
	b.uint(0)
	b.uint(0)
	b.uint(0)
	b.control(tokEndList)
	return b.buf
}

// startSessionCmd builds StartSession on the Session Manager opening spID. With a
// non-empty pin it authenticates in-session (HostChallenge + HostSigningAuthority);
// with an empty pin it opens an anonymous session, which the caller then elevates
// with Authenticate (authenticateCmd) — the path real drives that reject
// credential-in-StartSession (method status INVALID_PARAMETER) require.
func startSessionCmd(hsn uint32, spID UID, auth UID, pin []byte) []byte {
	return buildMethod(uidSMUID, uidMethodStartSession, func(b *builder) {
		startSessionArgs(b, hsn, spID, auth, pin)
	})
}

// startSessionArgs appends the StartSession parameters to b. It reserves all
// remaining space up front (startSessionReserve): no append after the PIN bytes
// are written may reallocate, or a stale copy of the PIN would be stranded in an
// unreachable backing array that zeroize cannot reach.
func startSessionArgs(b *builder, hsn uint32, spID, auth UID, pin []byte) {
	startSessionReserve(b, len(pin))
	b.uint(uint64(hsn)) // HostSessionID
	b.uid(spID)         // SPID
	b.uint(1)           // Write = TRUE
	if len(pin) == 0 {
		return // anonymous session: no HostChallenge/HostSigningAuthority
	}
	// HostChallenge (name 0) + HostSigningAuthority (name 3).
	b.control(tokStartName)
	b.uint(0)
	b.bytes(pin)
	b.control(tokEndName)
	b.control(tokStartName)
	b.uint(3)
	b.uid(auth)
	b.control(tokEndName)
}

// authenticateCmd builds the Authenticate method invoked on ThisSP within an open
// session: it elevates the session to the given authority using proof (the PIN) as
// the Challenge (optional parameter 0). Used after an anonymous StartSession.
func authenticateCmd(auth UID, proof []byte) []byte {
	return buildMethod(uidThisSP, uidMethodAuthenticate, func(b *builder) {
		startSessionReserve(b, len(proof))
		b.uid(auth) // authority to authenticate as
		b.control(tokStartName)
		b.uint(0) // Challenge
		b.bytes(proof)
		b.control(tokEndName)
	})
}

// startSessionReserve grows b so the remaining StartSession appends cannot
// reallocate the backing array. 64 bytes covers every token startSessionArgs
// emits besides the PIN itself (TestStartSessionGrowBudget pins that bound;
// TestStartSessionReserves pins that this reservation actually happens).
func startSessionReserve(b *builder, pinLen int) {
	b.grow(64 + pinLen)
}

// column is a single table cell value to write in a Set method.
type column struct {
	num uint64
	val uint64
}

// setCmd builds a Set on object invoker writing the given columns (the "Values"
// named parameter, name 1, holding a list of name=column value pairs).
func setCmd(invoker UID, cols ...column) []byte {
	return buildMethod(invoker, uidMethodSet, func(b *builder) {
		b.control(tokStartName)
		b.uint(1) // "Values"
		b.control(tokStartList)
		for _, c := range cols {
			b.control(tokStartName)
			b.uint(c.num)
			b.uint(c.val)
			b.control(tokEndName)
		}
		b.control(tokEndList)
		b.control(tokEndName)
	})
}

// propertiesCmd builds the Communication Properties method (Properties on the
// Session Manager) advertising the host's ComPacket/token limits. TCG Core encodes
// the HostProperties optional parameter (name 0) as a list of string-named uints.
// The advertised limits are conservative and consistent with recvBufSize
// (MaxComPacketSize). The basic (non-extended) set is sent, matching how the
// reference go-tcg-storage opens these drives (WithoutExtendedProperties).
func propertiesCmd() []byte {
	return buildMethod(uidSMUID, uidMethodProperties, func(b *builder) {
		b.control(tokStartName)
		b.uint(0) // HostProperties (optional parameter 0)
		b.control(tokStartList)
		b.namedUint("MaxMethods", 1)
		b.namedUint("MaxSubpackets", 1)
		b.namedUint("MaxPacketSize", recvBufSize-20)
		b.namedUint("MaxPackets", 1)
		b.namedUint("MaxComPacketSize", recvBufSize)
		b.namedUint("MaxIndTokenSize", recvBufSize-20-24-12)
		b.control(tokEndList)
		b.control(tokEndName)
	})
}

// methodResultBool reports the first integer of a method's result (the value
// before EndOfData) as a boolean — e.g. the Authenticate success flag. A missing
// result value is an error (fail closed).
func methodResultBool(payload []byte) (bool, error) {
	toks, err := tokenize(payload)
	if err != nil {
		return false, err
	}
	for _, tk := range toks {
		if tk.isControl(tokEndOfData) {
			break
		}
		if tk.isInt {
			return tk.u != 0, nil
		}
	}
	return false, fmt.Errorf("%w: no result value", ErrMethod)
}

// methodStatus extracts the status code from a method-result token stream: the
// first integer of the status list immediately after EndOfData.
func methodStatus(payload []byte) (uint64, error) {
	toks, err := tokenize(payload)
	if err != nil {
		return 0, err
	}
	for i, tk := range toks {
		if tk.isControl(tokEndOfData) {
			// Expect: EndOfData StartList <status> ...
			if i+2 >= len(toks) || !toks[i+1].isControl(tokStartList) || !toks[i+2].isInt {
				return 0, fmt.Errorf("%w: missing status list", ErrMethod)
			}
			return toks[i+2].u, nil
		}
	}
	return 0, fmt.Errorf("%w: no EndOfData", ErrMethod)
}

// checkStatus maps a method-result stream to an error unless the status is success.
func checkStatus(payload []byte) error {
	st, err := methodStatus(payload)
	if err != nil {
		return err
	}
	if st != statusSuccess {
		return fmt.Errorf("%w: status 0x%02x", ErrMethod, st)
	}
	return nil
}

// syncSessionIDs parses a SyncSession result, returning the host and TPer session
// numbers. Layout: Call SMUID SyncSession StartList <HSN> <TSN> ... ; the two
// integers at list positions 0 and 1 are HSN and TSN.
func syncSessionIDs(payload []byte) (hsn, tsn uint32, err error) {
	if err := checkStatus(payload); err != nil {
		return 0, 0, err
	}
	toks, err := tokenize(payload)
	if err != nil {
		return 0, 0, err
	}
	// Find the argument StartList (after Call, invoker, method).
	for i := 0; i+2 < len(toks); i++ {
		if toks[i].isControl(tokStartList) {
			if !toks[i+1].isInt || !toks[i+2].isInt {
				return 0, 0, fmt.Errorf("%w: SyncSession missing session ids", ErrMethod)
			}
			// These are device-supplied token integers (up to a full uint64), so
			// range-check before narrowing: silently truncating would let a TPer
			// echoing e.g. HSN 0x1_0000_0001 pass the host-session-id match.
			if toks[i+1].u > math.MaxUint32 || toks[i+2].u > math.MaxUint32 {
				return 0, 0, fmt.Errorf("%w: SyncSession session id exceeds 32 bits", ErrMethod)
			}
			return uint32(toks[i+1].u), uint32(toks[i+2].u), nil
		}
		if toks[i].isControl(tokEndOfData) {
			break
		}
	}
	return 0, 0, fmt.Errorf("%w: SyncSession malformed", ErrMethod)
}
