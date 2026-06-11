package opal

import (
	"errors"
	"testing"
)

func TestUnlockHappyPath(t *testing.T) {
	dev := NewMockTPer([]byte("correct horse"))
	c := NewClient(dev)

	if err := c.Unlock(AuthorityAdmin1, []byte("correct horse")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if dev.Locked() {
		t.Error("drive still locked after unlock")
	}
	if !dev.MBRDone() {
		t.Error("MBRDone not set after unlock")
	}
}

func TestUnlockFailsClosed(t *testing.T) {
	t.Run("wrong password", func(t *testing.T) {
		dev := NewMockTPer([]byte("right"))
		err := NewClient(dev).Unlock(AuthorityAdmin1, []byte("wrong"))
		if err == nil {
			t.Fatal("expected error on wrong password")
		}
		if !dev.Locked() {
			t.Error("drive must stay locked on auth failure")
		}
		if dev.MBRDone() {
			t.Error("MBRDone must not be set on auth failure")
		}
	})

	t.Run("unsupported feature (no locking)", func(t *testing.T) {
		dev := NewMockTPer([]byte("pw"))
		dev.LockingSupported = false
		if err := NewClient(dev).Unlock(AuthorityAdmin1, []byte("pw")); err == nil {
			t.Fatal("expected error when locking unsupported")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		dev := NewMockTPer([]byte("pw"))
		dev.Inject(FaultTimeout)
		if err := NewClient(dev).Unlock(AuthorityAdmin1, []byte("pw")); !errors.Is(err, ErrTimeout) {
			t.Fatalf("want ErrTimeout, got %v", err)
		}
		if !dev.Locked() {
			t.Error("drive must stay locked on timeout")
		}
	})

	t.Run("malformed response", func(t *testing.T) {
		dev := NewMockTPer([]byte("pw"))
		dev.Inject(FaultMalformed)
		// Discovery still works (separate ComID); the failure surfaces at the first
		// session exchange. Must fail closed, not panic.
		if err := NewClient(dev).Unlock(AuthorityAdmin1, []byte("pw")); err == nil {
			t.Fatal("expected error on malformed response")
		}
		if !dev.Locked() {
			t.Error("drive must stay locked on malformed response")
		}
	})

	t.Run("unknown authority", func(t *testing.T) {
		dev := NewMockTPer([]byte("pw"))
		if err := NewClient(dev).Unlock(Authority(99), []byte("pw")); err == nil {
			t.Fatal("expected error on unknown authority")
		}
	})

	t.Run("success status but no session id", func(t *testing.T) {
		dev := NewMockTPer([]byte("pw"))
		c := NewClient(syncSessionTransport{dev, statusSuccess, 1, 0})
		if err := c.Unlock(AuthorityAdmin1, []byte("pw")); err == nil {
			t.Fatal("a SyncSession with TSN 0 must be rejected")
		}
		if !dev.Locked() {
			t.Error("drive must stay locked")
		}
	})

	// F-M2: a non-success SyncSession status must be rejected even when the TPer
	// supplies a valid (non-zero) TSN. Without the checkStatus call in
	// syncSessionIDs this passes the TSN==0 and HSN guards and would be accepted as
	// an authenticated session.
	t.Run("failure status with valid session id", func(t *testing.T) {
		dev := NewMockTPer([]byte("pw"))
		c := NewClient(syncSessionTransport{dev, statusAuthLockedOut, 1, 0x1000})
		if err := c.Unlock(AuthorityAdmin1, []byte("pw")); err == nil {
			t.Fatal("a failure-status SyncSession must be rejected even with a non-zero TSN")
		}
		if !dev.Locked() {
			t.Error("drive must stay locked on failure-status SyncSession")
		}
	})

	// F-L3: the host-session-id echo check must reject a SyncSession whose HSN does
	// not match the one we sent (session confusion), independent of the TSN guard.
	t.Run("mismatched host session id", func(t *testing.T) {
		dev := NewMockTPer([]byte("pw"))
		c := NewClient(syncSessionTransport{dev, statusSuccess, 2, 0x1000})
		if err := c.Unlock(AuthorityAdmin1, []byte("pw")); err == nil {
			t.Fatal("a SyncSession echoing the wrong HSN must be rejected")
		}
		if !dev.Locked() {
			t.Error("drive must stay locked on HSN mismatch")
		}
	})
}

// syncSessionTransport serves the real discovery but replies to the session
// exchange with a crafted SyncSession (status, HSN, TSN), modelling a
// malicious/buggy TPer. It generalises zeroTSNTransport for the status/HSN guards.
type syncSessionTransport struct {
	base     *MockTPer
	status   uint64
	hsn, tsn uint32
}

func (s syncSessionTransport) Send(proto uint8, comID uint16, data []byte) error {
	return s.base.Send(proto, comID, data)
}

func (s syncSessionTransport) Recv(proto uint8, comID uint16, size int) ([]byte, error) {
	if comID == comIDDiscovery {
		return s.base.Recv(proto, comID, size)
	}
	return encodePacket(0x07fe, 0, 0, syncSessionStream(s.status, s.hsn, s.tsn)), nil
}

func TestUnlockSkipsMBRWhenDone(t *testing.T) {
	dev := NewMockTPer([]byte("pw"))
	dev.mbrDone = true // already done; Unlock must not need to set it again
	if err := NewClient(dev).Unlock(AuthorityAdmin1, []byte("pw")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if dev.Locked() {
		t.Error("drive still locked")
	}
	// The point of the guard (client.go: MBREnabled && !MBRDone): no MBRControl Set
	// is issued when MBRDone is already set. The mock's Set is idempotent, so without
	// this count the test would pass even if Unlock always sent the Set.
	if dev.mbrSets != 0 {
		t.Errorf("Unlock sent %d MBRControl Set(s) though MBRDone was already true; want 0", dev.mbrSets)
	}
}
