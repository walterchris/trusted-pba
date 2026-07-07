// SED unlock wiring (Phase 6, ADR-0009). This file has no build tags so the
// decision logic is host-testable: the tamago entrypoint injects the real UEFI
// Storage Security transport constructor, host tests inject mocks.

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/walterchris/trusted-pba/internal/credential"
	"github.com/walterchris/trusted-pba/internal/opal"
	"github.com/walterchris/trusted-pba/internal/policy"
)

// banner prefixes every console/serial line the PBA emits.
const banner = "TRUSTED-PBA"

// newCredentialSource builds the credential.Source unlockSED resolves the seed
// from, mapping the policy's stated source (ADR-0011 §2) to its implementation:
//   - policy-pin: the compiled-in debug PIN (takes ownership of cred.PIN bytes).
//   - console: the interactive pre-boot passphrase prompt (via env.Console).
//   - keyfile: the unlock seed read from the ESP / boot volume (via env.Files).
//
// It fails closed on an unknown source. It is a package variable so host tests
// can inject a source that fails closed on Resolve; production maps from the
// compiled-in policy. There is no fallback chain — one policy, one source
// (ADR-0011 §5).
var newCredentialSource = func(cred *policy.Credential) (credential.Source, error) {
	switch cred.Source {
	case policy.CredentialPolicyPIN:
		return credential.NewPolicyPIN([]byte(cred.PIN)), nil
	case policy.CredentialConsole:
		return credential.NewConsole(), nil
	case policy.CredentialKeyFile:
		return credential.NewKeyFile(cred.Path), nil
	default:
		return nil, fmt.Errorf("unknown credential source %q", cred.Source)
	}
}

// unlockSED enforces the policy's SED unlock gate before any chainload.
//
//   - policy.SEDUnlockNone: skip the unlock, but log it loudly — skipping is an
//     explicit policy decision, never a silent fallback (CLAUDE.md).
//   - anything else (SEDUnlockRequired, the parse-normalized default): construct
//     the transport and run the full fail-closed unlock. A missing Storage
//     Security device is a hard failure.
//
// Fail-closed caller contract (#51 item 2): on ANY error — no transport, auth
// failure, partial unlock (range cleared but MBRDone failed) — the caller must
// terminate via the policy's on-error action. It must never proceed to
// chainload and never retry into boot; reboot/halt leaves the drive to its
// locked-on-reset state rather than re-driving a half-unlocked session.
//
// PIN handling: the credential comes from a credential.Source selected from
// pol.SEDCredential (ADR-0011 §2 — policy-pin over the compiled-in PIN, or the
// interactive console source). The policy-pin bytes are handed to the source and
// the credential's PIN field is cleared so pol no longer holds the credential.
// The resolved seed is handed to Unlock exactly once (raw derive) or consumed by
// the derive into a new key that Unlock then consumes (sedutil-pbkdf2; the "auto"
// mode derives + attempts Unlock once per candidate iteration count, each key
// scrubbed after its attempt — see unlockWithDerive). Unlock zeroizes whichever
// slice it receives. Deferred clears cover the paths Unlock never sees the slice
// (resolve/derive/transport/select failure) and are idempotent after Unlock's own
// zeroization. No other copy is made here.
//
// derive (ADR-0011 §3) is applied AFTER the drive is selected, because the
// sedutil-pbkdf2 salt is the selected drive's serial: raw sends the seed
// unchanged (today's behavior); sedutil-pbkdf2 derives PBKDF2-HMAC-SHA512 over the
// seed with the drive serial as salt. The serial comes from the selected
// transport's optional credential.Serialer capability; today's Storage-Security
// carrier does not implement it, so sedutil-pbkdf2 fails closed until the
// NVMe-passthru carrier (A4b) supplies it.
//
// env carries the platform capabilities the source may need (the console
// Prompter); the tamago entrypoint builds the real one, host tests inject a mock.
//
// Errors never carry the PIN or session material (enforced for the opal layer
// by its log-scrub test); only the failing stage is reported.
func unlockSED(pol *policy.Policy, env credential.Env, newTransports func() ([]opal.Transport, error), w io.Writer) error {
	if pol.SEDUnlock == policy.SEDUnlockNone {
		// Console write errors are not actionable pre-boot; the decision itself
		// is what matters.
		_, _ = fmt.Fprintf(w, "%s: sed unlock not required by policy\r\n", banner)
		return nil
	}

	// Parse guarantees a credential for a required unlock, but guard anyway: a
	// nil credential here must fail closed, never unlock without one.
	cred := pol.SEDCredential
	if cred == nil {
		return errors.New("sed unlock failed: policy requires unlock but has no credential")
	}

	// The source takes ownership of cred.PIN (policy-pin) or none (console); clear
	// the credential's PIN so pol no longer holds a secret.
	src, err := newCredentialSource(cred)
	if err != nil {
		return fmt.Errorf("sed unlock failed: credential: %w", err)
	}
	pol.SEDCredential.PIN = nil
	seed, err := src.Resolve(env)
	if err != nil {
		return fmt.Errorf("sed unlock failed: credential %s: %w", src.Kind(), err)
	}
	defer clear(seed)

	transports, err := newTransports()
	if err != nil {
		return fmt.Errorf("sed unlock failed: transport: %w", err)
	}

	// A multi-NVMe machine exposes one Storage Security carrier per drive; only the
	// Opal SED answers Level-0 Discovery (the others fail with a device error). Pick
	// it before authenticating — Unlock consumes and zeroizes the credential, so it
	// can run on exactly one transport. (Targeting a specific drive among several
	// SEDs is a future refinement — ADR-0009.) The selected transport is also the
	// source of the sedutil-pbkdf2 salt (the drive serial), so derive follows it.
	client, selected, err := selectSED(transports, w)
	if err != nil {
		return fmt.Errorf("sed unlock failed: %w", err)
	}

	// derive + unlock after selection: raw and explicit sedutil-pbkdf2 derive once
	// and attempt Unlock once (behavior identical to today's single-attempt path);
	// sedutil-pbkdf2 "auto" tries each candidate iteration count best-first, stopping
	// on the first that authenticates and failing closed otherwise. Every derived key
	// is zeroized on every path.
	if err := unlockWithDerive(client, cred, seed, selected, w); err != nil {
		return fmt.Errorf("sed unlock failed: %w", err)
	}
	_, _ = fmt.Fprintf(w, "%s: sed unlock ok\r\n", banner)
	return nil
}

// sedutilPBKDF2AutoIterations is the fixed best-first candidate list the
// sedutil-pbkdf2 "auto" mode tries (#112). Best-first (the lumentum/v1.15 default
// 500000 first) so the common case authenticates on attempt #1 and burns no extra
// Admin1 try-limit; the older upstream default (75000) is only reached on a
// genuinely non-default drive. Keep it small and fixed — extend only when a third
// real-world value appears (a large list is an unacceptable try-limit exposure for
// a pre-boot product; ADR-0011 §3 / #112).
var sedutilPBKDF2AutoIterations = []int{500000, 75000}

// unlocker is the single Opal capability unlockWithDerive needs: attempt an
// authenticated unlock with a credential (consuming and zeroizing it). *opal.Client
// satisfies it; host tests inject a fake to drive the auto loop's control flow
// (advance on NOT_AUTHORIZED, stop on lockout/other) without hand-building TCG
// streams. Defined here (accept interfaces) where it is consumed.
type unlocker interface {
	Unlock(opal.Authority, []byte) error
}

// unlockWithDerive derives the drive credential from the seed per the policy's
// derive stage and attempts the Opal unlock, failing closed on every error path:
//
//   - raw / explicit sedutil-pbkdf2: derive once (raw = the seed unchanged;
//     sedutil-pbkdf2 = PBKDF2 with the resolved iteration count + key length) and
//     attempt Unlock exactly once — identical control flow to today.
//   - sedutil-pbkdf2 "auto": derive + attempt Unlock for each candidate iteration
//     count in sedutilPBKDF2AutoIterations, best-first. It advances ONLY on a
//     NOT_AUTHORIZED result (wrong iteration count → try the next); it stops
//     immediately and fails closed on AUTHORITY_LOCKED_OUT (further tries are futile
//     and burn the try-limit) or any other error (transport, malformed — never
//     masked by advancing). Exhausting the list is a fail-closed error.
//
// The salt (drive serial) is read once via the transport's optional
// credential.Serialer capability; today's Storage-Security carrier does not
// implement it, so sedutil-pbkdf2 fails closed until the NVMe-passthru carrier
// (A4b) supplies it. Unlock consumes and zeroizes the key it receives; this scrubs
// the seed once consumed and scrubs every derived key on every path (F-2). It never
// logs the iteration count or any credential in normal output — the winning count is
// emitted only under the hwdbg gate.
func unlockWithDerive(client unlocker, cred *policy.Credential, seed []byte, t opal.Transport, w io.Writer) error {
	if cred.Derive == policy.DeriveRaw {
		// The seed is the credential; Unlock consumes and zeroizes it. The caller's
		// deferred clear(seed) then runs idempotently.
		return client.Unlock(opal.AuthorityAdmin1, seed)
	}
	if cred.Derive != policy.DeriveSedutilPBKDF2 {
		// Parse rejects unknown derive values; guard the boot path regardless.
		return fmt.Errorf("derive: unknown derive %q", cred.Derive)
	}

	// sedutil-pbkdf2: the salt is the drive serial, read exactly once (not per
	// attempt). The seed is consumed by the derivation; scrub it once done here (the
	// caller's deferred clear then runs idempotently).
	defer clear(seed)
	s, ok := t.(credential.Serialer)
	if !ok {
		return errors.New("derive: drive serial unavailable: sedutil-pbkdf2 needs the NVMe-passthru carrier (A4b)")
	}
	salt, err := s.Serial()
	if err != nil {
		return fmt.Errorf("derive: drive serial: %w", err)
	}
	keyLen := cred.ResolvedKeyLen()

	count, auto := cred.ResolvedIterations()
	if !auto {
		key, err := applyDerive(seed, salt, count, keyLen)
		if err != nil {
			return fmt.Errorf("derive: %w", err)
		}
		defer clear(key)
		return client.Unlock(opal.AuthorityAdmin1, key)
	}

	// auto: try each candidate iteration count best-first.
	for _, iterations := range sedutilPBKDF2AutoIterations {
		key, err := applyDerive(seed, salt, iterations, keyLen)
		if err != nil {
			return fmt.Errorf("derive: %w", err)
		}
		err = client.Unlock(opal.AuthorityAdmin1, key)
		clear(key) // scrub whether or not Unlock already zeroized it (idempotent)
		if err == nil {
			if sedDebug {
				_, _ = fmt.Fprintf(w, "%s: [hwdbg] sedutil-pbkdf2 auto: authenticated at %d iterations\r\n", banner, iterations)
			}
			return nil
		}
		if errors.Is(err, opal.ErrNotAuthorized) {
			continue // wrong iteration count: try the next candidate
		}
		// Lockout or any other error: stop immediately, fail closed (never advance).
		return err
	}
	return errors.New("sedutil-pbkdf2 auto: no candidate iteration count authenticated")
}

// applyDerive runs the sedutil-pbkdf2 derivation for a single explicit iteration
// count and key length: PBKDF2-HMAC-SHA512 over the seed with the drive serial as
// salt (credential.SedutilPBKDF2), returning a NEW key buffer distinct from the
// seed. The caller owns and zeroizes both the seed and the returned key.
//
// It is a package variable so host tests can capture the derived buffer to assert it
// is zeroized after unlockSED (mirroring the newCredentialSource seam); production
// always uses applyDeriveImpl.
var applyDerive = applyDeriveImpl

func applyDeriveImpl(seed, salt []byte, iterations, keyLen int) ([]byte, error) {
	return credential.SedutilPBKDF2(seed, salt, iterations, keyLen)
}

// selectSED returns a client for the locked Opal SED among the Storage Security
// carriers — a drive reporting Opal SSC + locking-supported that is Locked with an
// active Shadow MBR — and the transport it was built on (so a salt-bearing derive
// can query that drive's credential.Serialer), and fails closed when none matches.
// Discovery is read-only and touches no credential, so probing the non-target
// carriers (which error) is harmless.
func selectSED(transports []opal.Transport, w io.Writer) (*opal.Client, opal.Transport, error) {
	// A machine can expose several Opal-capable NVMe drives (e.g. a blank SSD that
	// also answers Level-0 Discovery). The SED to unlock is the one that is locked
	// with an active Shadow MBR — the drive the PBA was booted from. Selecting the
	// first drive that merely answers Discovery is wrong (it can be a blank Opal disk).
	//
	// INTERIM (#81): this locked + Shadow-MBR heuristic is a stopgap — it also skips
	// an already-unlocked target. The rework ties selection to a specific drive
	// identity (boot device, or an NVMe serial/WWN from policy/config); see #81.
	// Discovery is read-only and PIN-free; it is re-run inside Unlock.
	for i, t := range transports {
		c := opal.NewClient(t)
		d, err := c.Discover()
		if sedDebug {
			if err != nil {
				_, _ = fmt.Fprintf(w, "%s: [hwdbg] dev %d/%d: discover error: %v\r\n", banner, i, len(transports), err)
			} else {
				_, _ = fmt.Fprintf(w, "%s: [hwdbg] dev %d/%d: OpalSSC=%t LockingSupported=%t Locked=%t MBREnabled=%t MBRDone=%t\r\n",
					banner, i, len(transports), d.OpalSSC, d.LockingSupported, d.Locked, d.MBREnabled, d.MBRDone)
			}
		}
		if err != nil || !d.OpalSSC || !d.LockingSupported {
			continue
		}
		if d.Locked && d.MBREnabled {
			return c, t, nil
		}
	}
	return nil, nil, fmt.Errorf("no locked Opal SED among %d storage security device(s)", len(transports))
}
