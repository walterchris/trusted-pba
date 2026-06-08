package transport

import (
	"errors"
	"testing"

	"github.com/walterchris/trusted-pba/internal/opal"
)

// TestHostFailsClosed verifies the off-target build has no usable carrier and the
// Opal client over it fails closed rather than pretending to talk to a drive.
func TestHostFailsClosed(t *testing.T) {
	if _, err := New(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("New on host: want ErrUnavailable, got %v", err)
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
