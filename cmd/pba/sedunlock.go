// SED unlock wiring (Phase 6, ADR-0009). This file has no build tags so the
// decision logic is host-testable: the tamago entrypoint injects the real UEFI
// Storage Security transport constructor, host tests inject mocks.

package main

import (
	"fmt"
	"io"

	"github.com/walterchris/trusted-pba/internal/opal"
	"github.com/walterchris/trusted-pba/internal/policy"
)

// banner prefixes every console/serial line the PBA emits.
const banner = "TRUSTED-PBA"

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
// PIN handling: the policy's PIN is moved out of pol and handed to Unlock
// exactly once, which consumes and zeroizes it. The deferred clear covers the
// one path Unlock never sees the slice (transport construction failure) and is
// idempotent after Unlock's own zeroization. No other copy is made here.
//
// Errors never carry the PIN or session material (enforced for the opal layer
// by its log-scrub test); only the failing stage is reported.
func unlockSED(pol *policy.Policy, newTransports func() ([]opal.Transport, error), w io.Writer) error {
	if pol.SEDUnlock == policy.SEDUnlockNone {
		// Console write errors are not actionable pre-boot; the decision itself
		// is what matters.
		_, _ = fmt.Fprintf(w, "%s: sed unlock not required by policy\r\n", banner)
		return nil
	}

	// TEMPORARY (#79) HW bring-up diagnostics — remove before merge.
	opal.Debugf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(w, "%s: opal-dbg: "+format+"\r\n", append([]any{banner}, args...)...)
	}

	pin := []byte(pol.SEDPIN)
	pol.SEDPIN = nil // pol must not remain a holder of the credential
	defer clear(pin)

	transports, err := newTransports()
	if err != nil {
		return fmt.Errorf("sed unlock failed: transport: %w", err)
	}

	// A multi-NVMe machine exposes one Storage Security carrier per drive; only the
	// Opal SED answers Level-0 Discovery (the others fail with a device error). Pick
	// it before authenticating — Unlock consumes and zeroizes the PIN, so it can run
	// on exactly one transport. (Targeting a specific drive among several SEDs is a
	// future refinement — ADR-0009.)
	client, err := selectSED(transports)
	if err != nil {
		return fmt.Errorf("sed unlock failed: %w", err)
	}
	if err := client.Unlock(opal.AuthorityAdmin1, pin); err != nil {
		return fmt.Errorf("sed unlock failed: %w", err)
	}
	_, _ = fmt.Fprintf(w, "%s: sed unlock ok\r\n", banner)
	return nil
}

// selectSED returns a client for the first transport whose Level-0 Discovery
// succeeds — the Opal SED among the Storage Security carriers — and fails closed
// when none responds. Discovery is read-only and touches no credential, so probing
// the non-SED carriers (which error) is harmless.
func selectSED(transports []opal.Transport) (*opal.Client, error) {
	for _, t := range transports {
		c := opal.NewClient(t)
		// Discovery is read-only and PIN-free; it both identifies the SED and is
		// re-run inside Unlock (which needs the fresh Discovery for the locking
		// state). The extra probe round-trip is intentional — do not "optimize" it
		// away by caching, or selection and unlock could diverge.
		if _, err := c.Discover(); err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no Opal SED among %d storage security device(s)", len(transports))
}
