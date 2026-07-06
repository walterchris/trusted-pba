package credential

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// mockPrompter is a scripted Prompter for the console-source tests. Each call to
// Passphrase returns the next queued reply (bytes + optional error). It records
// every buffer it handed out so tests can assert the source zeroized them on the
// error/abort paths (the #101 carry-over ownership contract).
type mockPrompter struct {
	replies []reply
	calls   int
	handed  [][]byte // every non-nil buffer returned, for zeroization assertions
}

type reply struct {
	pin []byte
	err error
}

func (m *mockPrompter) Passphrase(string) ([]byte, error) {
	if m.calls >= len(m.replies) {
		m.calls++
		return nil, errors.New("mockPrompter: unexpected extra call")
	}
	r := m.replies[m.calls]
	m.calls++
	if r.pin != nil {
		m.handed = append(m.handed, r.pin)
	}
	return r.pin, r.err
}

// assertHandedZeroized fails if any buffer the prompter returned still holds
// non-zero bytes — i.e. the source did not zeroize it.
func (m *mockPrompter) assertHandedZeroized(t *testing.T) {
	t.Helper()
	for i, b := range m.handed {
		for j, c := range b {
			if c != 0 {
				t.Errorf("prompter buffer %d not zeroized at byte %d", i, j)
				break
			}
		}
	}
}

func TestConsoleResolveAccepts(t *testing.T) {
	t.Parallel()
	want := []byte("correct horse")
	m := &mockPrompter{replies: []reply{{pin: append([]byte(nil), want...)}}}

	got, err := NewConsole().Resolve(Env{Console: m})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Resolve returned %q, want %q", got, want)
	}
	if m.calls != 1 {
		t.Errorf("prompted %d times, want 1 (accept on first non-empty)", m.calls)
	}
}

func TestConsoleResolveEmptyThenAccepts(t *testing.T) {
	t.Parallel()
	want := []byte("second try")
	m := &mockPrompter{replies: []reply{
		{pin: []byte{}},
		{pin: append([]byte(nil), want...)},
	}}

	got, err := NewConsole().Resolve(Env{Console: m})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Resolve returned %q, want %q", got, want)
	}
	if m.calls != 2 {
		t.Errorf("prompted %d times, want 2 (one empty reprompt)", m.calls)
	}
}

func TestConsoleResolveAllEmptyFailsClosed(t *testing.T) {
	t.Parallel()
	m := &mockPrompter{replies: []reply{{pin: []byte{}}, {pin: []byte{}}, {pin: []byte{}}}}

	got, err := NewConsole().Resolve(Env{Console: m})
	if err == nil {
		t.Fatal("all-empty input: want error, got nil")
	}
	if !errors.Is(err, errConsoleEmpty) {
		t.Errorf("want errConsoleEmpty, got %v", err)
	}
	if got != nil {
		t.Errorf("must return no bytes on failure, got %q", got)
	}
	if m.calls != maxConsoleAttempts {
		t.Errorf("prompted %d times, want the %d-attempt cap (bounded interactivity)", m.calls, maxConsoleAttempts)
	}
}

func TestConsoleResolvePrompterErrorFailsClosed(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("input device fault")
	// The prompter returns a partial secret buffer alongside the error; the source
	// must zeroize it before failing closed.
	partial := []byte("half-typed secret")
	m := &mockPrompter{replies: []reply{{pin: partial, err: sentinel}}}

	got, err := NewConsole().Resolve(Env{Console: m})
	if !errors.Is(err, sentinel) {
		t.Fatalf("want wrapped prompter error, got %v", err)
	}
	if got != nil {
		t.Errorf("must return no bytes on error, got %q", got)
	}
	m.assertHandedZeroized(t)
	if strings.Contains(err.Error(), "half-typed secret") {
		t.Errorf("error leaked the partial passphrase: %v", err)
	}
}

func TestConsoleResolveNilConsoleFailsClosed(t *testing.T) {
	t.Parallel()
	got, err := NewConsole().Resolve(Env{})
	if !errors.Is(err, errConsoleUnavailable) {
		t.Fatalf("want errConsoleUnavailable, got %v", err)
	}
	if got != nil {
		t.Errorf("must return no bytes when no console, got %q", got)
	}
}

func TestConsoleKind(t *testing.T) {
	t.Parallel()
	if got := NewConsole().Kind(); got != "console" {
		t.Errorf("Kind = %q, want %q", got, "console")
	}
}

// TestConsoleResolveNoSecretInErrors asserts none of the console source's
// fail-closed errors carry a passphrase, and Kind never does either.
func TestConsoleResolveNoSecretInErrors(t *testing.T) {
	t.Parallel()
	const secret = "topsecret"
	for _, err := range []error{errConsoleUnavailable, errConsoleEmpty} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q must not carry a secret", err)
		}
	}
}
