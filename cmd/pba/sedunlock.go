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
// The resolved seed is handed to Unlock exactly once, which consumes and
// zeroizes it. The deferred clear covers the paths Unlock never sees the slice
// (resolve/derive/transport-construction failure) and is idempotent after
// Unlock's own zeroization. No other copy is made here.
//
// derive (ADR-0011 §3) is applied after the source resolves the seed: raw sends
// it unchanged (today's behavior); sedutil-pbkdf2 is not implemented until A4
// (#104) and fails closed here.
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
	pin, err := src.Resolve(env)
	if err != nil {
		return fmt.Errorf("sed unlock failed: credential %s: %w", src.Kind(), err)
	}
	defer clear(pin)

	pin, err = applyDerive(cred.Derive, pin)
	if err != nil {
		return fmt.Errorf("sed unlock failed: derive: %w", err)
	}

	transports, err := newTransports()
	if err != nil {
		return fmt.Errorf("sed unlock failed: transport: %w", err)
	}

	// A multi-NVMe machine exposes one Storage Security carrier per drive; only the
	// Opal SED answers Level-0 Discovery (the others fail with a device error). Pick
	// it before authenticating — Unlock consumes and zeroizes the PIN, so it can run
	// on exactly one transport. (Targeting a specific drive among several SEDs is a
	// future refinement — ADR-0009.)
	client, err := selectSED(transports, w)
	if err != nil {
		return fmt.Errorf("sed unlock failed: %w", err)
	}
	if err := client.Unlock(opal.AuthorityAdmin1, pin); err != nil {
		return fmt.Errorf("sed unlock failed: %w", err)
	}
	_, _ = fmt.Fprintf(w, "%s: sed unlock ok\r\n", banner)
	return nil
}

// applyDerive turns the source's resolved seed into the raw drive credential per
// the policy's derive stage (ADR-0011 §3):
//   - raw (the parse-normalized default): the seed is the credential — returned
//     unchanged, so the caller's single deferred zeroization still covers it.
//   - sedutil-pbkdf2: not implemented until A4 (#104); fails closed so a policy
//     that selects it can never silently send the wrong (raw) credential to the
//     drive. It returns no bytes; the caller's deferred clear zeroizes the seed.
//
// A4 HAZARD: the caller's `defer clear(pin)` snapshots the SEED slice (registered
// before this reassignment). raw is safe because it returns that same backing.
// When A4 makes this return a NEW derived buffer, A4 MUST zeroize that buffer
// itself (the seed's deferred clear will not cover it) and add a test for it.
//
// Any other value is a fail-closed error (Parse already rejects unknown values;
// this guards the boot path regardless).
func applyDerive(d policy.Derive, seed []byte) ([]byte, error) {
	switch d {
	case policy.DeriveRaw:
		return seed, nil
	case policy.DeriveSedutilPBKDF2:
		return nil, errors.New("sedutil-pbkdf2 derive not implemented (A4, #104)")
	default:
		return nil, fmt.Errorf("unknown derive %q", d)
	}
}

// selectSED returns a client for the locked Opal SED among the Storage Security
// carriers — a drive reporting Opal SSC + locking-supported that is Locked with an
// active Shadow MBR — and fails closed when none matches. Discovery is read-only and
// touches no credential, so probing the non-target carriers (which error) is harmless.
func selectSED(transports []opal.Transport, w io.Writer) (*opal.Client, error) {
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
			return c, nil
		}
	}
	return nil, fmt.Errorf("no locked Opal SED among %d storage security device(s)", len(transports))
}
