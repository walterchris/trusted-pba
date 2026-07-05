package credential

import (
	"bytes"
	"fmt"
	"testing"
)

// TestPolicyPINResolveReturnsPIN checks the source hands back exactly the PIN
// bytes it was constructed with.
func TestPolicyPINResolveReturnsPIN(t *testing.T) {
	t.Parallel()
	want := []byte("correct horse")
	src := NewPolicyPIN(append([]byte(nil), want...))

	got, err := src.Resolve(Env{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Resolve returned %q, want %q", got, want)
	}
}

// TestPolicyPINResolveTransfersOwnership checks the source retains no copy after
// Resolve: zeroizing the returned slice leaves nothing behind, and a second
// Resolve yields nil.
func TestPolicyPINResolveTransfersOwnership(t *testing.T) {
	t.Parallel()
	src := NewPolicyPIN([]byte("secret pin"))

	pin, err := src.Resolve(Env{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The caller zeroizes its slice; the source must not hold another copy.
	clear(pin)

	again, err := src.Resolve(Env{})
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if again != nil {
		t.Errorf("source retained the secret after Resolve: %q", again)
	}
}

// TestPolicyPINResolveHandsBackBackingArray checks Resolve transfers the very
// backing array (not a copy), so the caller's single zeroization covers it.
func TestPolicyPINResolveHandsBackBackingArray(t *testing.T) {
	t.Parallel()
	backing := []byte("shared backing")
	src := NewPolicyPIN(backing)

	pin, err := src.Resolve(Env{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	clear(pin)
	for i, b := range backing {
		if b != 0 {
			t.Fatalf("backing array not zeroized at byte %d — Resolve copied instead of transferring", i)
		}
	}
}

// TestPolicyPINKind checks Kind is the stable name and never the secret.
func TestPolicyPINKind(t *testing.T) {
	t.Parallel()
	src := NewPolicyPIN([]byte("correct horse"))
	if got := src.Kind(); got != "policy-pin" {
		t.Errorf("Kind = %q, want %q", got, "policy-pin")
	}
}

// TestPolicyPINDoesNotLeakOnFormat checks that formatting the source (%v/%s/%q)
// never exposes the PIN — no accidental Stringer or field print leaks it.
func TestPolicyPINDoesNotLeakOnFormat(t *testing.T) {
	t.Parallel()
	const secret = "correct horse"
	src := NewPolicyPIN([]byte(secret))

	// The logging/error verbs a real code path would use. %#v (Go-syntax debug)
	// dumps raw struct fields for any type and is out of scope, exactly as it is
	// for policy.PIN's []byte backing.
	for _, verb := range []string{"%v", "%s", "%q", "%+v"} {
		s := fmt.Sprintf(verb, src)
		if bytes.Contains([]byte(s), []byte(secret)) {
			t.Errorf("format %q leaked the PIN: %s", verb, s)
		}
	}
}
