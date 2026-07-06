package transport

import (
	"errors"
	"testing"

	"github.com/walterchris/trusted-pba/internal/credential"
	"github.com/walterchris/trusted-pba/internal/opal"
)

// NVMe must expose the drive serial (the sedutil-pbkdf2 salt) via
// credential.Serialer in every build. This assertion lives in a test file so the
// non-test transport package never imports internal/credential (ADR-0004
// layering); the method set is identical across build tags.
var _ credential.Serialer = (*NVMe)(nil)

// TestHostFailsClosed verifies the off-target build has no usable carrier and the
// Opal client over it fails closed rather than pretending to talk to a drive.
func TestHostFailsClosed(t *testing.T) {
	if _, err := NewAll(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewAll on host: want ErrUnavailable, got %v", err)
	}

	var u UEFI
	if err := u.Send(0x01, 0x07fe, []byte{0x00}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Send: want ErrUnavailable, got %v", err)
	}
	if _, err := u.Recv(0x01, 0x07fe, 64); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Recv: want ErrUnavailable, got %v", err)
	}

	// The Opal client must surface the transport error (fail closed), not unlock.
	if err := opal.NewClient(&u).Unlock(opal.AuthorityAdmin1, []byte("pw")); err == nil {
		t.Error("Unlock over an unavailable transport must fail")
	}
}

// TestNVMeHostFailsClosed verifies the off-target NVMe carrier has no usable
// device and every method (incl. the Serialer salt source) fails closed, so a
// sedutil-pbkdf2 policy can never proceed off-target.
func TestNVMeHostFailsClosed(t *testing.T) {
	if _, err := NewAllNVMe(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewAllNVMe on host: want ErrUnavailable, got %v", err)
	}

	var n NVMe
	if err := n.Send(0x01, 0x07fe, []byte{0x00}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Send: want ErrUnavailable, got %v", err)
	}
	if _, err := n.Recv(0x01, 0x07fe, 64); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Recv: want ErrUnavailable, got %v", err)
	}
	if _, err := n.Serial(); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Serial: want ErrUnavailable, got %v", err)
	}

	// The Opal client must surface the transport error (fail closed), not unlock.
	if err := opal.NewClient(&n).Unlock(opal.AuthorityAdmin1, []byte("pw")); err == nil {
		t.Error("Unlock over an unavailable NVMe transport must fail")
	}
}
