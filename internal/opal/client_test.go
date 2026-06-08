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
}
