// SED unlock seed-derivation primitives (ADR-0011 §3, A4/#104). This file has no
// build tags so the derivation is host-unit-testable with a known-answer vector,
// and it carries no UEFI/Opal dependency — credential material must not mix into
// Opal protocol code (CLAUDE.md layering).

package credential

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"errors"
	"fmt"
)

// SedutilPBKDF2 DEFAULT parameters, matching the sedutil build that provisioned the
// common target drives. They MUST equal that sedutil's compile-time constants
// exactly, or the derived key will not match the drive credential and unlock fails
// closed. Callers use them when the policy leaves derive_params unspecified (the
// backward-compatible default); an explicit policy may override the iteration count
// or, with #112's "auto" mode, try several (see cmd/pba/sedunlock.go).
//
// Confirmed against the sedutil source in use (A4/#104): PBKDF2-HMAC-SHA512,
// 500000 iterations, 32-byte derived key. They are named constants (not literals)
// because sedutil versions differ (A4b/#112: upstream builds default to 75000).
// ADR-0011 §3 records an earlier SHA-1/75000 sketch that predates verifying the
// real source — the values here supersede it.
const (
	// SedutilPBKDF2Iterations is sedutil's default PBKDF2 iteration count.
	SedutilPBKDF2Iterations = 500000
	// SedutilPBKDF2KeyLen is sedutil's default derived-key length in bytes.
	SedutilPBKDF2KeyLen = 32
)

// SedutilPBKDF2 derives the raw drive credential from an unlock seed the
// sedutil-compatible way (ADR-0011 §3): PBKDF2-HMAC-SHA512 over the seed with the
// drive's serial number as the salt, using iterations iterations and a keyLen-byte
// output. The iteration count and key length are parameters (#112) because sedutil
// versions differ; callers pass the policy-resolved values, defaulting to
// SedutilPBKDF2Iterations / SedutilPBKDF2KeyLen when the policy leaves them
// unspecified. They MUST match the sedutil build that provisioned the drive or the
// derived key will not match and unlock fails closed. salt is the drive's 20-byte
// serial number exactly as sedutil supplies it (raw, space-padded, unmodified); the
// caller must pass it verbatim so the derived key matches what sedutil stored.
//
// It fails closed on an empty seed, empty salt, a non-positive iteration count, or a
// non-positive key length: sedutil produces no hash for an empty password, so an
// empty seed must never be turned into a credential; a missing serial (empty salt)
// must never silently derive against a degenerate salt; and a degenerate iteration
// count or key length must never derive a weak/empty credential. The policy layer
// also validates these, but the primitive guards regardless. The caller owns and
// zeroizes the returned key.
//
// Note: crypto/pbkdf2.Key takes the password as a string, so the seed is copied
// into an immutable Go string for the duration of the call; that transient copy
// cannot be zeroized (same class of unscrubable copy as the transport/firmware
// buffers documented in opal.Transport). The caller's seed slice is still
// zeroized by the caller; only the returned derived key is under this function's
// control and is what the caller must scrub.
func SedutilPBKDF2(seed, salt []byte, iterations, keyLen int) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("empty unlock seed")
	}
	if len(salt) == 0 {
		return nil, errors.New("empty salt (drive serial)")
	}
	if iterations <= 0 {
		return nil, fmt.Errorf("non-positive pbkdf2 iterations %d", iterations)
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("non-positive pbkdf2 key length %d", keyLen)
	}
	key, err := pbkdf2.Key(sha512.New, string(seed), salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2: %w", err)
	}
	return key, nil
}

// Serialer is the optional capability a transport MAY implement to supply the
// drive's serial number for salt-bearing derivations (sedutil-pbkdf2, ADR-0011
// §3). It is an optional capability discovered by type assertion, NOT part of the
// opal.Transport interface (ADR-0004 layering): the Storage-Security carrier does
// not implement it, so a sedutil-pbkdf2 policy fails closed until the NVMe-passthru
// carrier (A4b) provides it. Defined here because the derive path is its only
// consumer.
type Serialer interface {
	// Serial returns the drive's serial number to use as the PBKDF2 salt (the
	// 20-byte serial, raw and space-padded as the drive reports it), or fails
	// closed with an error. It is read-only and touches no credential.
	Serial() ([]byte, error)
}
