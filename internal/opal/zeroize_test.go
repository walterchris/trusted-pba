package opal

import (
	"bytes"
	"testing"
)

// spyTransport wraps the mock TPer, recording an alias (not a copy) of every
// frame passed to Send plus whether it carried the secret at transmit time, so
// tests can observe that the client zeroized those buffers afterwards.
type spyTransport struct {
	*MockTPer
	secret []byte
	frames []sentFrame
}

type sentFrame struct {
	data      []byte // alias of the client's frame buffer
	hadSecret bool   // frame contained the PIN when it was sent
}

func (s *spyTransport) Send(proto uint8, comID uint16, data []byte) error {
	s.frames = append(s.frames, sentFrame{data, bytes.Contains(data, s.secret)})
	return s.MockTPer.Send(proto, comID, data)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// assertZeroized checks that the caller's pin and every transmitted frame were
// zeroed, and that the spy actually saw the PIN on the wire (i.e. the assertion
// is observing the real auth exchange, not vacuously passing).
func assertZeroized(t *testing.T, spy *spyTransport, pin []byte) {
	t.Helper()
	if !allZero(pin) {
		t.Errorf("caller pin not zeroized: %x", pin)
	}
	var sawSecret bool
	for i, f := range spy.frames {
		if f.hadSecret {
			sawSecret = true
		}
		if !allZero(f.data) {
			t.Errorf("transmitted frame %d not zeroized after use", i)
		}
	}
	if !sawSecret {
		t.Error("no transmitted frame carried the PIN — spy is not observing the auth exchange")
	}
}

func TestUnlockZeroizesSecrets(t *testing.T) {
	t.Run("successful auth", func(t *testing.T) {
		pin := []byte("correct horse")
		spy := &spyTransport{MockTPer: NewMockTPer([]byte("correct horse")), secret: []byte("correct horse")}
		if err := NewClient(spy).Unlock(AuthorityAdmin1, pin); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		assertZeroized(t, spy, pin)
	})

	t.Run("failed auth", func(t *testing.T) {
		pin := []byte("wrong pin")
		spy := &spyTransport{MockTPer: NewMockTPer([]byte("right pin")), secret: []byte("wrong pin")}
		if err := NewClient(spy).Unlock(AuthorityAdmin1, pin); err == nil {
			t.Fatal("expected auth failure")
		}
		assertZeroized(t, spy, pin)
	})

	t.Run("failure before the auth exchange", func(t *testing.T) {
		pin := []byte("pw")
		dev := NewMockTPer([]byte("pw"))
		dev.Inject(FaultTimeout)
		if err := NewClient(dev).Unlock(AuthorityAdmin1, pin); err == nil {
			t.Fatal("expected timeout error")
		}
		if !allZero(pin) {
			t.Errorf("pin not zeroized after early failure: %x", pin)
		}
	})
}

func TestTransactZeroizesMethodPayload(t *testing.T) {
	newSession := func(t *testing.T) (*Client, *MockTPer, []byte) {
		t.Helper()
		dev := NewMockTPer([]byte("super secret"))
		c := NewClient(dev)
		if _, err := c.Discover(); err != nil {
			t.Fatalf("Discover: %v", err)
		}
		cmd := startSessionCmd(1, uidLockingSP, uidAuthAdmin1, []byte("super secret"))
		if !bytes.Contains(cmd, []byte("super secret")) {
			t.Fatal("sanity: method payload must embed the PIN before transact")
		}
		return c, dev, cmd
	}

	t.Run("success", func(t *testing.T) {
		c, _, cmd := newSession(t)
		if _, err := c.transact(0, 0, cmd); err != nil {
			t.Fatalf("transact: %v", err)
		}
		if !allZero(cmd) {
			t.Errorf("method payload not zeroized after transact: %x", cmd)
		}
	})

	t.Run("send failure", func(t *testing.T) {
		c, dev, cmd := newSession(t)
		dev.Inject(FaultTimeout)
		if _, err := c.transact(0, 0, cmd); err == nil {
			t.Fatal("expected transport error")
		}
		if !allZero(cmd) {
			t.Errorf("method payload not zeroized after failed transact: %x", cmd)
		}
	})
}

func TestBuilderGrowPreventsReallocation(t *testing.T) {
	var b builder
	b.uint(7)
	b.grow(64)
	p := &b.buf[0]
	for range 64 {
		b.control(tokEmpty)
	}
	if p != &b.buf[0] {
		t.Error("append reallocated despite grow — a stale secret copy would be stranded")
	}
}
