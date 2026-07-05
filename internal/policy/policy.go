// Package policy is the PBA boot-trust policy: which second-stage image to boot
// and how it is validated. The policy is compiled into the binary (embedded JSON,
// see embed.go) and parsed fail-closed — any malformed or invalid policy yields an
// error and no usable policy, so the caller refuses to boot.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ValidationMode is how a boot entry's image is validated before it is started.
type ValidationMode string

const (
	// Firmware lets the firmware (Secure Boot) validate the image: the PBA just
	// calls LoadImage/StartImage — the Windows Boot Manager path.
	Firmware ValidationMode = "firmware"
	// PBA means the PBA validates the image itself (Authenticode vs embedded
	// db/dbx) before loading, via internal/imageverify.
	PBA ValidationMode = "pba"
	// PBAOverride is PBA validation plus a SHIM-style Secure Boot override so the
	// image loads even when firmware db would reject it (a platform trusting only
	// our PBA key). The PBA verifies the image, then authorizes exactly that buffer
	// to the firmware via an EFI_SECURITY2_ARCH_PROTOCOL override (ADR-0012). It is
	// compiled only with -tags trustbroker and diverges PCR 7 (not for BitLocker
	// targets); without the tag a pba-override entry fails closed at chainload.
	PBAOverride ValidationMode = "pba-override"
)

// BootEntry is one candidate boot target.
type BootEntry struct {
	Name       string         `json:"name"`
	Path       string         `json:"path"` // ESP-relative, e.g. "EFI/TEST/TESTAPP.EFI"
	Validation ValidationMode `json:"validation"`
}

// SEDUnlock is whether the PBA must unlock a TCG Opal SED before chainloading.
// There is no implicit behavior: an absent field means SEDUnlockRequired (fail
// closed), and skipping the unlock requires the explicit SEDUnlockNone statement,
// which the boot path logs loudly (never a silent fallback). See ADR-0009.
type SEDUnlock string

const (
	// SEDUnlockRequired means the boot path must successfully unlock the SED
	// (Discovery0, authenticated session, range unlock, MBRDone) before any
	// chainload. This is the default when the field is absent.
	SEDUnlockRequired SEDUnlock = "required"
	// SEDUnlockNone means this deployment has no Opal device to unlock (e.g.
	// non-SED machines, virtual tests without a Storage Security device). It is
	// an explicit, logged policy decision — never an implicit fallback.
	SEDUnlockNone SEDUnlock = "none"
)

// PIN is an SED credential as raw bytes. It decodes from a plain JSON string
// (not the base64 a []byte field would require) so the compiled-in test policy
// stays human-readable, and is held as bytes — not a string — so the boot path
// can zeroize it after use. MVP only: the compiled-in policy carrying the PIN is
// replaced by real authentication before any production deployment (ADR-0009).
type PIN []byte

// String implements fmt.Stringer and always returns "[redacted]", enforcing the
// non-negotiable "never log passwords, PINs, keys" rule (CLAUDE.md) structurally:
// any future %v/%s of a PIN — or of a Policy containing one — cannot leak the
// credential.
func (PIN) String() string { return "[redacted]" }

// UnmarshalJSON decodes a JSON string into the PIN bytes.
func (p *PIN) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("sed_pin must be a string: %w", err)
	}
	*p = PIN(s)
	return nil
}

// OnError is the terminal action taken on any fail-closed decision. Every option
// stays fail-closed: it MUST NOT return control to the firmware boot manager / next
// NVRAM boot entry (CLAUDE.md: never silently fall back to insecure behavior).
type OnError string

const (
	// OnErrorHalt dead-stops the CPU (the default).
	OnErrorHalt OnError = "halt"
	// OnErrorShutdown powers the machine off.
	OnErrorShutdown OnError = "shutdown"
	// OnErrorReboot resets the machine, which re-runs the PBA from the start
	// (never the firmware's next boot option).
	OnErrorReboot OnError = "reboot"
)

// Policy is the compiled-in boot-trust policy.
type Policy struct {
	RequireSecureBoot bool        `json:"require_secure_boot"`
	Entries           []BootEntry `json:"entries"`
	// OnError is the action on any fail-closed decision; empty means OnErrorHalt.
	OnError OnError `json:"on_error"`
	// SEDUnlock gates the SED unlock step; empty means SEDUnlockRequired (fail
	// closed — only an explicit "none" skips the unlock).
	SEDUnlock SEDUnlock `json:"sed_unlock"`
	// SEDPIN is the Admin1 credential for the unlock. MVP: the compiled-in test
	// policy carries it (plan §7.1); the boot path consumes and zeroizes it.
	SEDPIN PIN `json:"sed_pin"`
}

// Sentinel errors.
var (
	ErrNoEntries          = errors.New("policy has no boot entries")
	ErrSecureBootRequired = errors.New("policy requires Secure Boot enforcing")
)

// Parse decodes and validates a JSON policy. It fails closed: malformed input,
// unknown fields, or an invalid entry return an error and no policy. Parse never
// panics on arbitrary input (see the fuzz test).
func Parse(data []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if dec.More() {
		return nil, errors.New("decode policy: unexpected trailing data")
	}
	if len(p.Entries) == 0 {
		return nil, ErrNoEntries
	}
	switch p.OnError {
	case "":
		p.OnError = OnErrorHalt
	case OnErrorHalt, OnErrorShutdown, OnErrorReboot:
	default:
		return nil, fmt.Errorf("unknown on_error %q", p.OnError)
	}
	switch p.SEDUnlock {
	case "":
		p.SEDUnlock = SEDUnlockRequired // absence = required: fail closed
	case SEDUnlockRequired, SEDUnlockNone:
	default:
		return nil, fmt.Errorf("unknown sed_unlock %q", p.SEDUnlock)
	}
	// MVP: the policy is the PIN source, so "required" without a PIN can never
	// unlock — reject it at parse time instead of failing at the drive. "none"
	// must not embed a stray credential.
	if p.SEDUnlock == SEDUnlockRequired && len(p.SEDPIN) == 0 {
		return nil, errors.New("sed_unlock is required but sed_pin is empty")
	}
	if p.SEDUnlock == SEDUnlockNone && len(p.SEDPIN) != 0 {
		return nil, errors.New("sed_pin set but sed_unlock is none")
	}
	for i, e := range p.Entries {
		if e.Name == "" || e.Path == "" {
			return nil, fmt.Errorf("entry %d: name and path are required", i)
		}
		switch e.Validation {
		case Firmware, PBA, PBAOverride:
		default:
			return nil, fmt.Errorf("entry %q: unknown validation mode %q", e.Name, e.Validation)
		}
	}
	return &p, nil
}

// Select returns the boot entry to use: the first (primary) entry. Selecting
// among multiple entries by availability is not yet implemented.
func (p *Policy) Select() (BootEntry, error) {
	if len(p.Entries) == 0 {
		return BootEntry{}, ErrNoEntries
	}
	return p.Entries[0], nil
}

// CheckSecureBoot fails closed when the policy requires Secure Boot enforcement but
// the firmware is not enforcing (CLAUDE.md: never treat Secure Boot disabled and
// enabled as equivalent).
func (p *Policy) CheckSecureBoot(enforcing bool) error {
	if p.RequireSecureBoot && !enforcing {
		return ErrSecureBootRequired
	}
	return nil
}

// CheckReleaseReady reports whether this policy is safe to embed in a RELEASE
// build. It is deliberately stricter than Parse: the development defaults that
// Parse accepts — Secure Boot not required, sed_unlock "none", a test-fixture
// boot target — are legitimate for virtual testing but must never ship, because
// a shipped policy is baked into the signed, measured artifact and cannot be
// changed at runtime.
//
// It is NOT part of the boot path; the release gate (Taskfile check-release-policy)
// calls it so an unsafe default cannot silently reach a release artifact. All
// violations are joined so a release engineer sees every problem at once.
//
// Note on require_secure_boot: an *absent* field parses to false (the Go zero
// value), which this treats as unsafe — the opposite of a permissive default.
// Only an explicit true passes.
func (p *Policy) CheckReleaseReady() error {
	var errs []error
	if !p.RequireSecureBoot {
		errs = append(errs, errors.New(`require_secure_boot must be true (absent or false is unsafe: firmware-mode validation does nothing when Secure Boot is off)`))
	}
	if p.SEDUnlock == SEDUnlockNone {
		errs = append(errs, errors.New(`sed_unlock must not be "none" (a release must never silently skip the SED unlock)`))
	}
	for _, e := range p.Entries {
		if isTestFixturePath(e.Path) {
			errs = append(errs, fmt.Errorf("entry %q targets test-fixture path %q — not for a release build", e.Name, e.Path))
		}
	}
	return errors.Join(errs...)
}

// isTestFixturePath reports whether an ESP-relative path is the virtual-test boot
// fixture (EFI/TEST/...), which must never be a release boot target.
func isTestFixturePath(path string) bool {
	return strings.HasPrefix(strings.ToUpper(path), "EFI/TEST/")
}
