package opal

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
)

// Log-scrub assertions for #51 item 1: the PIN (which is also the session's
// HostChallenge — it is sent verbatim as the StartSession HostChallenge
// parameter) must never reach console/serial output.
//
// The opal layer's invariant is stronger than scrubbing: it is SILENT. It never
// writes to stdout, stderr, or the log package — all console/serial output in
// this program goes through cmd/pba's `out` writer, and the only opal-originated
// text that can reach it is the error value Unlock returns, which main prints.
// So these tests assert both halves:
//
//  1. a full Unlock exchange writes nothing to file descriptors 1 and 2 (the
//     capture must be empty — silence subsumes scrubbing at this layer), and
//  2. the returned error text never contains the PIN in any representation
//     (raw, hex, base64, decimal byte slice) — that error string is what
//     actually gets printed.

// markerPIN is distinctive enough that a leak into output or error text cannot
// be an accidental substring collision.
const markerPIN = "MARKER-PIN-3fa9c1d7e5"

// captureProcessOutput runs fn with file descriptors 1 and 2 redirected to an
// in-process pipe and returns everything written. The redirection must happen
// at the descriptor level: swapping the os.Stdout/os.Stderr variables would
// miss writers that hold the real descriptors — notably the runtime's builtin
// print/println, which write straight to fds 1/2. dup'ing the pipe over the
// fds catches every write path, including the log package's init-captured
// os.Stderr. Host-(Linux-)only; the opal tests never run under TamaGo.
func captureProcessOutput(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = r.Close() }()

	savedOut, err := syscall.Dup(syscall.Stdout)
	if err != nil {
		t.Fatalf("dup stdout: %v", err)
	}
	savedErr, err := syscall.Dup(syscall.Stderr)
	if err != nil {
		_ = syscall.Close(savedOut)
		t.Fatalf("dup stderr: %v", err)
	}

	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		// Best effort: a failure to restore the real fds cannot be reported
		// anywhere useful, and the saved descriptors are always valid here.
		_ = syscall.Dup3(savedOut, syscall.Stdout, 0)
		_ = syscall.Dup3(savedErr, syscall.Stderr, 0)
		_ = syscall.Close(savedOut)
		_ = syscall.Close(savedErr)
		_ = w.Close() // the reader sees EOF once fds 1/2 no longer alias the pipe
	}
	defer restore() // also runs when fn itself fails the test (t.Fatalf → Goexit)

	if err := syscall.Dup3(int(w.Fd()), syscall.Stdout, 0); err != nil {
		t.Fatalf("redirect stdout: %v", err)
	}
	if err := syscall.Dup3(int(w.Fd()), syscall.Stderr, 0); err != nil {
		t.Fatalf("redirect stderr: %v", err)
	}

	type capture struct {
		out     string
		readErr error
	}
	done := make(chan capture, 1) // buffered: the goroutine never blocks, even if the test bails out
	go func() {
		b, err := io.ReadAll(r)
		done <- capture{string(b), err}
	}()

	fn()
	restore()
	c := <-done
	if c.readErr != nil {
		t.Fatalf("read captured output: %v", c.readErr)
	}
	return c.out
}

// secretEncodings returns the representations under which the PIN must never
// appear in output: raw bytes, lower/upper hex, the base64 variants, and Go's
// default byte-slice formatting ("[77 65 ...]", what %v/%d/fmt.Sprint print).
func secretEncodings(pin []byte) map[string]string {
	h := hex.EncodeToString(pin)
	return map[string]string{
		"raw bytes":     string(pin),
		"hex":           h,
		"HEX":           strings.ToUpper(h),
		"base64":        base64.StdEncoding.EncodeToString(pin),
		"base64url":     base64.URLEncoding.EncodeToString(pin),
		"base64 no pad": base64.RawStdEncoding.EncodeToString(pin),
		"decimal slice": fmt.Sprintf("%d", pin),
	}
}

// assertScrubbed fails if any representation of pin appears in text. It
// deliberately does not echo text on failure, so a leak does not propagate the
// secret into test logs.
func assertScrubbed(t *testing.T, channel, text string, pin []byte) {
	t.Helper()
	for name, enc := range secretEncodings(pin) {
		if strings.Contains(text, enc) {
			t.Errorf("%s leaks the PIN (as %s)", channel, name)
		}
	}
}

func TestUnlockEmitsNoConsoleOutput(t *testing.T) {
	scenarios := []struct {
		name    string
		device  func() Transport
		wantErr bool
	}{
		{
			name:   "successful auth",
			device: func() Transport { return NewMockTPer([]byte(markerPIN)) },
		},
		{
			name:    "wrong pin",
			device:  func() Transport { return NewMockTPer([]byte("a different credential")) },
			wantErr: true,
		},
		{
			name: "transport timeout",
			device: func() Transport {
				dev := NewMockTPer([]byte(markerPIN))
				dev.Inject(FaultTimeout)
				return dev
			},
			wantErr: true,
		},
		{
			name: "malformed response after the PIN was transmitted",
			device: func() Transport {
				dev := NewMockTPer([]byte(markerPIN))
				dev.Inject(FaultMalformed) // discovery works; the session Recv fails
				return dev
			},
			wantErr: true,
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			out := captureProcessOutput(t, func() {
				pin := []byte(markerPIN) // fresh copy: Unlock consumes pin
				err = NewClient(tc.device()).Unlock(AuthorityAdmin1, pin)
			})

			if tc.wantErr && err == nil {
				t.Fatal("expected Unlock to fail")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Unlock: %v", err)
			}

			// The opal layer must be silent: any output at all is a violation,
			// secret-bearing or not.
			if out != "" {
				t.Errorf("opal layer wrote %d bytes to process output; it must be silent", len(out))
			}
			assertScrubbed(t, "process output", out, []byte(markerPIN))

			// The error is what cmd/pba prints to console/serial — scrub it.
			if err != nil {
				assertScrubbed(t, "error text", err.Error(), []byte(markerPIN))
			}
		})
	}
}
