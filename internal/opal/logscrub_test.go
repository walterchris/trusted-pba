package opal

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"os"
	"strings"
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
//  1. a full Unlock exchange writes nothing to os.Stdout, os.Stderr, or the
//     default log output (the capture must be empty — silence subsumes
//     scrubbing at this layer), and
//  2. the returned error text never contains the PIN in any representation
//     (raw, hex, base64) — that error string is what actually gets printed.

// markerPIN is distinctive enough that a leak into output or error text cannot
// be an accidental substring collision.
var markerPIN = []byte("MARKER-PIN-3fa9c1d7e5")

// captureProcessOutput runs fn with os.Stdout, os.Stderr, and the default log
// writer redirected to an in-process pipe and returns everything written. The
// log package captures os.Stderr at init, so swapping the variables alone would
// miss it; log.SetOutput covers that path too.
func captureProcessOutput(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	log.SetOutput(w)
	defer func() {
		os.Stdout, os.Stderr = oldOut, oldErr
		log.SetOutput(os.Stderr)
	}()

	captured := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		captured <- string(b)
	}()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	return <-captured
}

// secretEncodings returns the representations under which the PIN must never
// appear in output: raw bytes, lower/upper hex, and the base64 variants.
func secretEncodings(pin []byte) map[string]string {
	h := hex.EncodeToString(pin)
	return map[string]string{
		"raw bytes":     string(pin),
		"hex":           h,
		"HEX":           strings.ToUpper(h),
		"base64":        base64.StdEncoding.EncodeToString(pin),
		"base64url":     base64.URLEncoding.EncodeToString(pin),
		"base64 no pad": base64.RawStdEncoding.EncodeToString(pin),
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
			device: func() Transport { return NewMockTPer(markerPIN) },
		},
		{
			name:    "wrong pin",
			device:  func() Transport { return NewMockTPer([]byte("a different credential")) },
			wantErr: true,
		},
		{
			name: "transport timeout",
			device: func() Transport {
				dev := NewMockTPer(markerPIN)
				dev.Inject(FaultTimeout)
				return dev
			},
			wantErr: true,
		},
		{
			name: "malformed response after the PIN was transmitted",
			device: func() Transport {
				dev := NewMockTPer(markerPIN)
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
				pin := append([]byte(nil), markerPIN...) // Unlock consumes pin
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
			assertScrubbed(t, "process output", out, markerPIN)

			// The error is what cmd/pba prints to console/serial — scrub it.
			if err != nil {
				assertScrubbed(t, "error text", err.Error(), markerPIN)
			}
		})
	}
}
