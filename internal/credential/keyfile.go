package credential

import (
	"errors"
	"fmt"
	"io/fs"
)

// errFilesUnavailable is returned when no filesystem capability is present.
var errFilesUnavailable = errors.New("no filesystem available to read the keyfile")

// errKeyFileEmpty is returned when the keyfile exists but is empty — an empty key
// is never a valid credential, so it fails closed. It never carries file bytes.
var errKeyFileEmpty = errors.New("keyfile is empty")

// keyfile is the file-backed Source (ADR-0011 §4): it reads the unlock seed from a
// file on the boot volume / ESP (env.Files) at a fixed path. The secret lives at
// rest on the volume — a low-assurance, operational-simplicity source (ADR-0011
// §4/§Security Impact: the key stays extractable from the volume). It fails closed
// on an absent filesystem, a read error, or an empty file, and zeroizes any buffer
// it holds on the error paths (the caller owns and zeroizes the returned bytes on
// success). It never logs the key bytes; errors carry only the stage and the path
// (a path is not secret).
type keyfile struct{ path string }

// NewKeyFile returns the file-backed Source reading the unlock seed from path on
// env.Files (the boot-volume / ESP filesystem). path is ESP-relative (e.g.
// "EFI/KEY/sed.key"). It carries no secret; the key is read on Resolve and handed
// to the caller to zeroize.
func NewKeyFile(path string) Source { return keyfile{path: path} }

// Resolve reads the keyfile at the configured path from env.Files and returns its
// bytes as the unlock seed. It fails closed if no filesystem is present, if the
// read fails, or if the file is empty; on every error path it zeroizes any bytes
// it read so the key never escapes un-scrubbed. Only the non-empty read buffer is
// handed to the caller, who owns and zeroizes it. Errors carry the path but never
// the key bytes.
func (k keyfile) Resolve(env Env) ([]byte, error) {
	if env.Files == nil {
		return nil, errFilesUnavailable
	}
	data, err := fs.ReadFile(env.Files, k.path)
	if err != nil {
		// A partial read may have populated data alongside the error; zeroize it
		// before failing closed — never leave secret bytes un-scrubbed.
		clear(data)
		return nil, fmt.Errorf("read keyfile %q: %w", k.path, err)
	}
	if len(data) == 0 {
		clear(data) // nothing secret in an empty slice, but stay uniform
		return nil, fmt.Errorf("read keyfile %q: %w", k.path, errKeyFileEmpty)
	}
	return data, nil
}

// Kind returns "keyfile". It never returns the secret.
func (keyfile) Kind() string { return "keyfile" }
