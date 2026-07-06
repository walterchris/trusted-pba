package credential

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"
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

// errBoomRead is the read failure injected by partialReadFS.
var errBoomRead = errors.New("boom read error")

// partialReadFS is an fs.FS whose only file yields secret bytes and THEN a
// non-EOF error, so fs.ReadFile returns partial data alongside the error —
// exercising keyfile.Resolve's read-error scrub branch. It captures the buffer it
// was handed (which aliases fs.ReadFile's return buffer, which Resolve clears), so
// the test can prove the scrub ran: with clear(data) present the captured buffer
// is zeroed; drop the clear and it still holds the secret (mutation guard).
type partialReadFS struct {
	secret   []byte
	captured []byte // aliases the buffer Resolve reads into and must zeroize
}

func (p *partialReadFS) Open(string) (fs.File, error) { return &partialReadFile{fsys: p}, nil }

type partialReadFile struct {
	fsys *partialReadFS
	done bool
}

func (f *partialReadFile) Stat() (fs.FileInfo, error) {
	return fakeInfo{size: int64(len(f.fsys.secret))}, nil
}

func (f *partialReadFile) Read(p []byte) (int, error) {
	if f.done {
		return 0, errBoomRead
	}
	n := copy(p, f.fsys.secret)
	f.fsys.captured = p // capture the caller's buffer (aliases fs.ReadFile's)
	f.done = true
	return n, errBoomRead // partial data + non-EOF error
}

func (f *partialReadFile) Close() error { return nil }

type fakeInfo struct{ size int64 }

func (fakeInfo) Name() string       { return "sed.key" }
func (i fakeInfo) Size() int64      { return i.size }
func (fakeInfo) Mode() fs.FileMode  { return 0 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (fakeInfo) Sys() any           { return nil }

// TestKeyFileResolveReadErrorScrubs covers the read-error branch: Resolve must
// fail closed AND zeroize the partial secret it read (never leak it in the error).
func TestKeyFileResolveReadErrorScrubs(t *testing.T) {
	t.Parallel()
	const secret = "partialsecret"
	fsys := &partialReadFS{secret: []byte(secret)}

	got, err := NewKeyFile(keyFilePath).Resolve(Env{Files: fsys})
	if err == nil {
		t.Fatal("read error: want error, got nil")
	}
	if !errors.Is(err, errBoomRead) {
		t.Errorf("want wrapped errBoomRead, got %v", err)
	}
	if got != nil {
		t.Errorf("must return no bytes on a read error, got %q", got)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error %q must not carry the partial key", err)
	}
	// The buffer Resolve read into (captured alias) must be zeroized by clear(data).
	if bytes.Contains(fsys.captured, []byte(secret)) {
		t.Errorf("read-error path must zeroize the partial key buffer; still contains the secret")
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
