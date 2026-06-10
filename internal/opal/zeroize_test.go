package opal

import (
	"bytes"
	"errors"
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

// newSpy returns a spy transport over a fresh mock TPer provisioned with
// devicePIN, watching the wire for callerPIN, plus the mutable pin slice the
// test hands to Unlock (which consumes it).
func newSpy(devicePIN, callerPIN string) (*spyTransport, []byte) {
	spy := &spyTransport{MockTPer: NewMockTPer([]byte(devicePIN)), secret: []byte(callerPIN)}
	return spy, []byte(callerPIN)
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
		spy, pin := newSpy("correct horse", "correct horse")
		if err := NewClient(spy).Unlock(AuthorityAdmin1, pin); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		assertZeroized(t, spy, pin)
	})

	t.Run("failed auth", func(t *testing.T) {
		spy, pin := newSpy("right pin", "wrong pin")
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

	t.Run("malformed response after the PIN was transmitted", func(t *testing.T) {
		spy, pin := newSpy("super secret", "super secret")
		spy.Inject(FaultMalformed) // Send (carrying the PIN) succeeds; the session Recv fails to decode
		if err := NewClient(spy).Unlock(AuthorityAdmin1, pin); err == nil {
			t.Fatal("expected decode failure")
		}
		assertZeroized(t, spy, pin)
	})

	t.Run("transport failure mid-session after successful auth", func(t *testing.T) {
		spy, pin := newSpy("super secret", "super secret")
		if err := NewClient(&failAfterAuthTransport{spyTransport: spy}).Unlock(AuthorityAdmin1, pin); !errors.Is(err, ErrTimeout) {
			t.Fatalf("want ErrTimeout mid-session, got %v", err)
		}
		// Two sends prove the failure hit the in-session command, not StartSession.
		if len(spy.frames) < 2 {
			t.Fatalf("only %d frame(s) sent — the fault fired before auth completed", len(spy.frames))
		}
		assertZeroized(t, spy, pin)
	})
}

// failAfterAuthTransport lets the StartSession exchange (the frame carrying the
// PIN) succeed, then injects a timeout so the first in-session command fails:
// PIN-bearing buffers must be zeroized even when the session dies after a
// successful authentication.
type failAfterAuthTransport struct {
	*spyTransport
	sends int
}

func (f *failAfterAuthTransport) Send(proto uint8, comID uint16, data []byte) error {
	f.sends++
	if f.sends == 2 { // send 1: StartSession (succeeds); send 2: Set on the locking range
		f.Inject(FaultTimeout)
	}
	return f.spyTransport.Send(proto, comID, data)
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

// TestStartSessionGrowBudget pins the 64-byte reservation in startSessionCmd
// (method.go): everything the method appends after its grow call, beyond the
// PIN's own bytes, must fit in the reserved 64 bytes — otherwise an append
// could reallocate the backing array and strand an unreachable copy of the PIN
// that zeroize cannot reach. The budget was previously maintained only by a
// comment; this test measures it at the real call site with worst-case non-PIN
// inputs (maximum HSN, so the integer atom is largest).
func TestStartSessionGrowBudget(t *testing.T) {
	// Measure the fixed prefix buildMethod emits before the args callback runs
	// (i.e. before startSessionCmd's grow): Call + two 9-byte UID atoms +
	// StartList = 20 bytes today. Fail loudly if buildMethod changes shape.
	var prefixLen int
	buildMethod(uidSMUID, uidMethodStartSession, func(b *builder) { prefixLen = len(b.buf) })
	if prefixLen != 20 {
		t.Fatalf("pre-grow prefix is %d bytes, want 20 — buildMethod changed; re-derive this test's budget", prefixLen)
	}

	// nil PIN isolates the pure non-PIN overhead; the 2048-byte PIN forces the
	// largest byte-string atom header (4 bytes), which also comes out of the
	// 64-byte budget since grow only reserves 64+len(pin).
	for _, tc := range []struct {
		name string
		pin  []byte
	}{
		{"nil pin", nil},
		{"long-atom pin", make([]byte, 2048)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			overhead := len(startSessionCmd(^uint32(0), uidLockingSP, uidAuthAdmin1, tc.pin)) - prefixLen - len(tc.pin)
			if overhead > 64 {
				t.Errorf("startSessionCmd appends %d non-PIN bytes after grow; budget is 64 (method.go) — raise the reservation", overhead)
			}
		})
	}
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
