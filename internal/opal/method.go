package opal

import (
	"errors"
	"fmt"
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

// startSessionCmd builds StartSession on the Session Manager, authenticating with
// pin as the given authority against spID (the SP to open).
func startSessionCmd(hsn uint32, spID UID, auth UID, pin []byte) []byte {
	return buildMethod(uidSMUID, uidMethodStartSession, func(b *builder) {
		b.uint(uint64(hsn)) // HostSessionID
		b.uid(spID)         // SPID
		b.uint(1)           // Write = TRUE
		// HostChallenge (name 0) + HostSigningAuthority (name 3).
		b.control(tokStartName)
		b.uint(0)
		b.bytes(pin)
		b.control(tokEndName)
		b.control(tokStartName)
		b.uint(3)
		b.uid(auth)
		b.control(tokEndName)
	})
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
			return u32(toks[i+1].u), u32(toks[i+2].u), nil
		}
		if toks[i].isControl(tokEndOfData) {
			break
		}
	}
	return 0, 0, fmt.Errorf("%w: SyncSession malformed", ErrMethod)
}
