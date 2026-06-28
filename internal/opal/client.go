package opal

import (
	"encoding/binary"
	"fmt"
)

// Transport is the abstract TCG transport (the plan's TCGTransport): it carries
// raw IF-SEND / IF-RECV payloads to the drive, independent of UEFI. Implementations
// are the native mock (tests), the UEFI Storage Security protocol (Phase 5), and
// real hardware. Defined here because the Opal client is its only consumer.
type Transport interface {
	// Send issues an IF-SEND (Security Protocol Out) of data for the given security
	// protocol and ComID (SP-specific value). data may embed credentials (the
	// StartSession host challenge): an implementation must not retain data after
	// Send returns, because the client zeroizes it, and must zeroize any transient
	// Go-side copies of data it makes before returning. Copies made beyond the
	// transport boundary — firmware command buffers, device DMA — are outside the
	// client's reach and cannot be zeroized here.
	Send(proto uint8, comID uint16, data []byte) error
	// Recv issues an IF-RECV (Security Protocol In) and returns up to size bytes.
	Recv(proto uint8, comID uint16, size int) ([]byte, error)
}

// Security protocol IDs and the fixed Level 0 Discovery ComID.
const (
	protoSecurity   = 0x01   // SECURITY PROTOCOL 1 (TCG)
	protoComIDMgmt  = 0x02   // SECURITY PROTOCOL 2 (TCG ComID management)
	comIDDiscovery  = 0x0001 // Level 0 Discovery
	recvBufSize     = 2048   // IF-RECV transfer length
	comIDMgmtBufLen = 512    // ComID-management request/response buffer
)

// comIDRequestStackReset is the ComID-management request code that resets the
// synchronous protocol stack for a ComID (TCG Storage Core).
var comIDRequestStackReset = [4]byte{0x00, 0x00, 0x00, 0x02}

// Locking and MBRControl table column numbers (Opal SSC).
const (
	colReadLocked  = 7
	colWriteLocked = 8
	colMBRDone     = 2
)

// Client drives an Opal drive over a Transport. Not safe for concurrent use.
type Client struct {
	t     Transport
	comID uint16 // session ComID from discovery
	hsn   uint32 // host session number
	tsn   uint32 // TPer session number
}

// NewClient returns a client over t.
func NewClient(t Transport) *Client { return &Client{t: t} }

// Discover performs Level 0 Discovery and records the session ComID.
func (c *Client) Discover() (*Discovery, error) {
	raw, err := c.t.Recv(protoSecurity, comIDDiscovery, recvBufSize)
	if err != nil {
		return nil, fmt.Errorf("opal: discovery recv: %w", err)
	}
	d, err := parseDiscovery(raw)
	if err != nil {
		return nil, err
	}
	c.comID = d.BaseComID
	return d, nil
}

// Unlock performs the full fail-closed unlock flow: discover, open an authenticated
// Locking SP session, clear the global range read/write locks, set MBRDone if a
// Shadow MBR is shadowing, then close the session. Any step's failure aborts and
// returns an error (the caller must not boot).
//
// A non-nil error may leave the drive partially unlocked (e.g. the global range was
// cleared but setting MBRDone then failed). It is still fail-closed at the boot
// level — the caller must not chainload on error — but on error the caller should
// re-lock or halt rather than proceed or retry into boot (the Phase 5/6 wiring owns
// that contract).
//
// Unlock consumes pin: it is zeroed before Unlock returns, on success and on every
// error path. Callers must not reuse the slice and remain responsible for any
// other copies they hold (e.g. the console input buffer the PIN was read into).
func (c *Client) Unlock(auth Authority, pin []byte) error {
	defer zeroize(pin)

	d, err := c.Discover()
	if err != nil {
		return err
	}
	if !d.LockingSupported {
		return fmt.Errorf("opal: drive does not support locking")
	}

	// Bring the ComID to a known state before opening a session, mirroring the
	// TCG control-session setup: reset the synchronous protocol stack, then
	// negotiate Communication Properties. Real TPers reject StartSession
	// (INVALID_PARAMETER) without this; the mock TPers accept it too.
	if err := c.stackReset(); err != nil {
		return err
	}
	if err := c.properties(); err != nil {
		return err
	}

	authUID, ok := auth.uid()
	if !ok {
		return fmt.Errorf("opal: unknown authority %d", auth)
	}
	// Open an anonymous session, then elevate it with Authenticate. This drive
	// rejects the credential supplied inside StartSession (INVALID_PARAMETER), so
	// the credential is presented via the Authenticate method instead.
	if err := c.startSession(uidLockingSP, authUID, nil); err != nil {
		return err
	}
	defer c.endSession()
	if err := c.authenticate(authUID, pin); err != nil {
		return err
	}

	if err := c.set(uidGlobalRange, column{colReadLocked, 0}, column{colWriteLocked, 0}); err != nil {
		return fmt.Errorf("opal: unlock global range: %w", err)
	}
	if d.MBREnabled && !d.MBRDone {
		if err := c.set(uidMBRControl, column{colMBRDone, 1}); err != nil {
			return fmt.Errorf("opal: set MBRDone: %w", err)
		}
	}
	return nil
}

// startSession opens an authenticated session on spID and stores the session IDs.
func (c *Client) startSession(spID, auth UID, pin []byte) error {
	// A multi-byte Host Session Number: real drives reject a 1-byte tiny-atom HSN
	// (e.g. 1) with INVALID_PARAMETER. The PBA opens a single session per boot, so a
	// fixed value is fine (no collision concern).
	const hsn = 0x12345678
	resp, err := c.transact(0, 0, startSessionCmd(hsn, spID, auth, pin))
	if err != nil {
		return fmt.Errorf("opal: start session: %w", err)
	}
	gotHSN, tsn, err := syncSessionIDs(resp)
	if err != nil {
		return fmt.Errorf("opal: start session: %w", err)
	}
	if gotHSN != hsn {
		return fmt.Errorf("opal: start session: %w: host session id mismatch", ErrMethod)
	}
	// TSN 0 is the control session; a real session must have a non-zero TSN. Reject
	// a (success-status) SyncSession that omits it so later Sets cannot be issued on
	// the control session.
	if tsn == 0 {
		return fmt.Errorf("opal: start session: %w: TPer assigned no session id", ErrMethod)
	}
	c.hsn, c.tsn = gotHSN, tsn
	return nil
}

// set writes table columns on object invoker within the open session.
func (c *Client) set(invoker UID, cols ...column) error {
	resp, err := c.transact(c.tsn, c.hsn, setCmd(invoker, cols...))
	if err != nil {
		return err
	}
	return checkStatus(resp)
}

// stackReset resets the synchronous protocol stack for the ComID via a TCG ComID
// management request (security protocol 0x02), as the TCG control-session setup
// does before opening a session. The request carries the (extended) ComID and the
// stack-reset code; the response's success word (offset 12, big-endian) must be 0.
func (c *Client) stackReset() error {
	buf := make([]byte, comIDMgmtBufLen)
	binary.BigEndian.PutUint16(buf[0:2], c.comID)
	// buf[2:4] (extended ComID high bits) stays 0 for a 16-bit base ComID.
	copy(buf[4:8], comIDRequestStackReset[:])

	if err := c.t.Send(protoComIDMgmt, c.comID, buf); err != nil {
		return fmt.Errorf("opal: stack reset send: %w", err)
	}
	res, err := c.t.Recv(protoComIDMgmt, c.comID, comIDMgmtBufLen)
	if err != nil {
		return fmt.Errorf("opal: stack reset recv: %w", err)
	}
	// Response layout: [10:12] = payload size (BE), [12:] = payload; the stack-reset
	// payload's first word is the success code (0 = success).
	if len(res) < 16 {
		return fmt.Errorf("opal: stack reset: short response (%d bytes)", len(res))
	}
	if size := binary.BigEndian.Uint16(res[10:12]); size < 4 {
		return fmt.Errorf("opal: stack reset: pending or empty response (size %d)", size)
	}
	if binary.BigEndian.Uint32(res[12:16]) != 0 {
		return fmt.Errorf("opal: stack reset: TPer reported failure")
	}
	return nil
}

// authenticate elevates the open session to auth, presenting pin as the Challenge
// (the Authenticate method on ThisSP). It fails closed: a method error, a
// non-success status, or a false authenticate result is an authentication failure.
// The error never carries pin or session material.
func (c *Client) authenticate(auth UID, pin []byte) error {
	resp, err := c.transact(c.tsn, c.hsn, authenticateCmd(auth, pin))
	if err != nil {
		return fmt.Errorf("opal: authenticate: %w", err)
	}
	if err := checkStatus(resp); err != nil {
		return fmt.Errorf("opal: authenticate: %w", err)
	}
	ok, err := methodResultBool(resp)
	if err != nil {
		return fmt.Errorf("opal: authenticate: %w", err)
	}
	if !ok {
		return fmt.Errorf("opal: authenticate: %w", ErrNotAuthorized)
	}
	return nil
}

// properties runs the Communication Properties exchange on the control session
// (TSN 0, HSN 0): the host advertises its ComPacket/token limits to the TPer. Only
// the method status is checked — the host keeps its conservative recvBufSize, so the
// TPer's returned limits need not be parsed.
func (c *Client) properties() error {
	resp, err := c.transact(0, 0, propertiesCmd())
	if err != nil {
		return fmt.Errorf("opal: properties: %w", err)
	}
	return checkStatus(resp)
}

// endSession sends EndOfSession and clears the session state (best effort).
func (c *Client) endSession() {
	if c.tsn == 0 && c.hsn == 0 {
		return
	}
	frame := encodePacket(c.comID, c.tsn, c.hsn, []byte{tokEndOfSession})
	_ = c.t.Send(protoSecurity, c.comID, frame)
	zeroize(frame)
	_, _ = c.t.Recv(protoSecurity, c.comID, recvBufSize)
	c.tsn, c.hsn = 0, 0
}

// transact sends one method payload in a session packet and returns the decoded
// response payload. It consumes payload: both it and the transmitted frame are
// zeroed before transact returns, on success and on error, because the
// StartSession payload embeds the host credential.
func (c *Client) transact(tsn, hsn uint32, payload []byte) ([]byte, error) {
	frame := encodePacket(c.comID, tsn, hsn, payload)
	zeroize(payload) // already copied into frame; not used again
	defer zeroize(frame)
	if err := c.t.Send(protoSecurity, c.comID, frame); err != nil {
		return nil, fmt.Errorf("opal: send: %w", err)
	}
	raw, err := c.t.Recv(protoSecurity, c.comID, recvBufSize)
	if err != nil {
		return nil, fmt.Errorf("opal: recv: %w", err)
	}
	return decodePacket(raw)
}

// zeroize overwrites b with zeros so secret material — the PIN and the
// method/packet buffers embedding it — does not linger in memory after use.
// Copies beyond the transport boundary are out of reach; see Transport.Send.
func zeroize(b []byte) { clear(b) }
