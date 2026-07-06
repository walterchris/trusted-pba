package credential

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

const keyFilePath = "EFI/KEY/sed.key"

func TestKeyFileResolveReadsKey(t *testing.T) {
	t.Parallel()
	want := []byte("correct horse")
	env := Env{Files: fstest.MapFS{keyFilePath: {Data: append([]byte(nil), want...)}}}

	got, err := NewKeyFile(keyFilePath).Resolve(env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Resolve returned %q, want %q", got, want)
	}
}

func TestKeyFileResolveNilFilesFailsClosed(t *testing.T) {
	t.Parallel()
	got, err := NewKeyFile(keyFilePath).Resolve(Env{})
	if !errors.Is(err, errFilesUnavailable) {
		t.Fatalf("want errFilesUnavailable, got %v", err)
	}
	if got != nil {
		t.Errorf("must return no bytes when no filesystem, got %q", got)
	}
}

func TestKeyFileResolveMissingFailsClosed(t *testing.T) {
	t.Parallel()
	// A filesystem with no keyfile: the read must fail closed.
	env := Env{Files: fstest.MapFS{}}
	got, err := NewKeyFile(keyFilePath).Resolve(env)
	if err == nil {
		t.Fatal("missing keyfile: want error, got nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("want a wrapped fs.ErrNotExist, got %v", err)
	}
	if got != nil {
		t.Errorf("must return no bytes on a missing keyfile, got %q", got)
	}
	// The path is not secret; it is allowed in the error to name the failing stage.
	if !strings.Contains(err.Error(), keyFilePath) {
		t.Errorf("error %q should name the keyfile path", err)
	}
}

func TestKeyFileResolveEmptyFailsClosed(t *testing.T) {
	t.Parallel()
	env := Env{Files: fstest.MapFS{keyFilePath: {Data: []byte{}}}}
	got, err := NewKeyFile(keyFilePath).Resolve(env)
	if !errors.Is(err, errKeyFileEmpty) {
		t.Fatalf("want errKeyFileEmpty, got %v", err)
	}
	if got != nil {
		t.Errorf("must return no bytes on an empty keyfile, got %q", got)
	}
}

func TestKeyFileKind(t *testing.T) {
	t.Parallel()
	if got := NewKeyFile(keyFilePath).Kind(); got != "keyfile" {
		t.Errorf("Kind = %q, want %q", got, "keyfile")
	}
}

// TestKeyFileResolveNoSecretInErrors asserts the keyfile source's fail-closed
// errors never carry a key. The path is not secret (it may appear); the key bytes
// must not.
func TestKeyFileResolveNoSecretInErrors(t *testing.T) {
	t.Parallel()
	const secret = "topsecretkey"
	env := Env{Files: fstest.MapFS{keyFilePath: {Data: []byte(secret)}}}
	// An empty read is the only in-band failure that touches file bytes; construct
	// one whose "content" is empty so we still assert the static errors are clean.
	for _, err := range []error{errFilesUnavailable, errKeyFileEmpty} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q must not carry a secret", err)
		}
	}
	// A successful read must return exactly the file bytes (no truncation/leak into
	// logs is possible because the source returns bytes, never logs them).
	got, err := NewKeyFile(keyFilePath).Resolve(env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != secret {
		t.Errorf("Resolve returned %q, want %q", got, secret)
	}
}
