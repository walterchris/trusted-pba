package opal

import "fmt"

// Transport is the abstract TCG transport (the plan's TCGTransport): it carries
// raw IF-SEND / IF-RECV payloads to the drive, independent of UEFI. Implementations
// are the native mock (tests), the UEFI Storage Security protocol (Phase 5), and
// real hardware. Defined here because the Opal client is its only consumer.
type Transport interface {
	// Send issues an IF-SEND (Security Protocol Out) of data for the given security
	// protocol and ComID (SP-specific value).
	Send(proto uint8, comID uint16, data []byte) error
	// Recv issues an IF-RECV (Security Protocol In) and returns up to size bytes.
	Recv(proto uint8, comID uint16, size int) ([]byte, error)
}

// Security protocol IDs and the fixed Level 0 Discovery ComID.
const (
	protoSecurity  = 0x01   // SECURITY PROTOCOL 1 (TCG)
	comIDDiscovery = 0x0001 // Level 0 Discovery
	recvBufSize    = 2048   // IF-RECV transfer length
)

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
func (c *Client) Unlock(auth Authority, pin []byte) error {
	d, err := c.Discover()
	if err != nil {
		return err
	}
	if !d.LockingSupported {
		return fmt.Errorf("opal: drive does not support locking")
	}

	authUID, ok := auth.uid()
	if !ok {
		return fmt.Errorf("opal: unknown authority %d", auth)
	}
	if err := c.startSession(uidLockingSP, authUID, pin); err != nil {
		return err
	}
	defer c.endSession()

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
	const hsn = 1
	resp, err := c.transact(0, 0, startSessionCmd(hsn, spID, auth, pin))
	if err != nil {
		return fmt.Errorf("opal: start session: %w", err)
	}
	gotHSN, tsn, err := syncSessionIDs(resp)
	if err != nil {
		return fmt.Errorf("opal: start session: %w", err)
	}
	if gotHSN != hsn {
		return fmt.Errorf("opal: start session: host session id mismatch")
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

// endSession sends EndOfSession and clears the session state (best effort).
func (c *Client) endSession() {
	if c.tsn == 0 && c.hsn == 0 {
		return
	}
	_ = c.t.Send(protoSecurity, c.comID, encodePacket(c.comID, c.tsn, c.hsn, []byte{tokEndOfSession}))
	_, _ = c.t.Recv(protoSecurity, c.comID, recvBufSize)
	c.tsn, c.hsn = 0, 0
}

// transact sends one method payload in a session packet and returns the decoded
// response payload.
func (c *Client) transact(tsn, hsn uint32, payload []byte) ([]byte, error) {
	if err := c.t.Send(protoSecurity, c.comID, encodePacket(c.comID, tsn, hsn, payload)); err != nil {
		return nil, fmt.Errorf("opal: send: %w", err)
	}
	raw, err := c.t.Recv(protoSecurity, c.comID, recvBufSize)
	if err != nil {
		return nil, fmt.Errorf("opal: recv: %w", err)
	}
	return decodePacket(raw)
}
