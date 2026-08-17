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
	"path"
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

// PIN is an SED credential seed as raw bytes. It decodes from a plain JSON string
// (not the base64 a []byte field would require) so the compiled-in test policy
// stays human-readable, and is held as bytes — not a string — so the boot path
// can zeroize it after use. It is only carried by the policy-pin credential
// source (the compiled-in debug credential, release-gated — ADR-0011 §5); real
// deployments select an interactive/token source instead.
type PIN []byte

// String implements fmt.Stringer and always returns "[redacted]", enforcing the
// non-negotiable "never log passwords, PINs, keys" rule (CLAUDE.md) structurally:
// any future %v/%s of a PIN — or of a Policy containing one — cannot leak the
// credential.
func (PIN) String() string { return "[redacted]" }

// GoString implements fmt.GoStringer so the %#v verb also redacts. fmt does not
// consult Stringer for %#v, so without this a %#v of a PIN — or of a Policy
// containing one — would print the raw credential bytes (#122). The %d verb (a
// decimal byte list) still bypasses both, but has no consumer here (a []byte
// carries no default %d formatting) and is not a plausible accidental leak.
func (PIN) GoString() string { return "[redacted]" }

// UnmarshalJSON decodes a JSON string into the PIN bytes.
func (p *PIN) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("pin must be a string: %w", err)
	}
	*p = PIN(s)
	return nil
}

// CredentialSource selects where the SED unlock credential comes from (ADR-0011
// §1/§2). The policy states exactly one source — there is no fallback chain, so a
// weaker source can never rescue a failed stronger one (ADR-0011 §5).
type CredentialSource string

const (
	// CredentialPolicyPIN is the compiled-in-PIN debug source (ADR-0011 §5): the
	// Admin1 PIN is baked into the policy JSON. It is extractable from the signed
	// image, so CheckReleaseReady rejects it — it must never ship.
	CredentialPolicyPIN CredentialSource = "policy-pin"
	// CredentialConsole prompts the operator for the passphrase interactively at
	// the pre-boot console (ADR-0011 §4). No secret is stored at rest, so the
	// policy carries no PIN for this source.
	CredentialConsole CredentialSource = "console"
	// CredentialKeyFile reads the unlock seed from a file on the boot volume / ESP
	// (ADR-0011 §4). The policy carries the file Path (not the secret); the key
	// lives at rest on the volume, so it is a low-assurance source. It carries no
	// compiled-in PIN.
	CredentialKeyFile CredentialSource = "keyfile"
)

// Derive is the optional stage that turns the source's seed into the raw drive
// credential (ADR-0011 §3). It is orthogonal to the source.
type Derive string

const (
	// DeriveRaw sends the seed to the drive unchanged (today's behavior). It is
	// the default when derive is absent.
	DeriveRaw Derive = "raw"
	// DeriveSedutilPBKDF2 is sedutil's PBKDF2-HMAC-SHA512 derivation (salt = the
	// drive's serial), interoperable with sedutil-provisioned drives (incl. the customer fork). The
	// iteration count and key length default to 500000/32 and are tunable via
	// DeriveParams, including an "auto" mode (#104/#112). It needs a transport that
	// exposes the drive serial (credential.Serialer, the NVMe-passthru carrier); it
	// fails closed at unlock time otherwise.
	DeriveSedutilPBKDF2 Derive = "sedutil-pbkdf2"
)

// Credential is the SED unlock credential block (ADR-0011 §2), present only when
// sed_unlock is "required". Source selects where the credential comes from; PIN
// carries the compiled-in secret for the policy-pin source only; Derive is the
// optional derivation stage (empty means raw); DeriveParams tunes the sedutil-pbkdf2
// derivation (#112) and is valid only when Derive is sedutil-pbkdf2.
type Credential struct {
	Source       CredentialSource `json:"source"`
	PIN          PIN              `json:"pin,omitempty"`           // policy-pin only
	Path         string           `json:"path,omitempty"`          // keyfile only (ESP-relative)
	Derive       Derive           `json:"derive,omitempty"`        // empty => raw
	DeriveParams *DeriveParams    `json:"derive_params,omitempty"` // sedutil-pbkdf2 only (#112)
}

// Default sedutil-pbkdf2 derive parameters (#112). These duplicate
// credential.SedutilPBKDF2Iterations / credential.SedutilPBKDF2KeyLen deliberately:
// the policy layer must not import internal/credential (ADR-0004 layering — policy
// carries no crypto). Keep the two in sync; the credential package is authoritative.
const (
	defaultSedutilPBKDF2Iterations = 500000
	defaultSedutilPBKDF2KeyLen     = 32
	// maxSedutilPBKDF2Iterations bounds an explicit iteration count so a degenerate
	// or absurd value is rejected at parse rather than driving a pathological
	// derivation on the pre-boot path.
	maxSedutilPBKDF2Iterations = 100_000_000
	// maxSedutilPBKDF2KeyLen bounds an explicit key length (SHA-512 output is 64
	// bytes; a longer PBKDF2 output only repeats the KDF pointlessly).
	maxSedutilPBKDF2KeyLen = 64
)

// DeriveParams tunes the sedutil-pbkdf2 derivation (#112) so a deployment matches
// whatever sedutil provisioned its drives without rebuilding the PBA. Both fields
// are optional: an absent Iterations means the default count (or, with the "auto"
// spec, the best-first candidate list); an absent KeyLen (zero) means the default.
type DeriveParams struct {
	// Iterations is the PBKDF2 iteration count: an explicit positive integer, or the
	// string "auto" (try the known candidate counts best-first, ADR-0011 §3 / #112).
	Iterations IterationSpec `json:"iterations,omitempty"`
	// KeyLen is the derived-key length in bytes; zero (absent) means the default.
	KeyLen int `json:"key_len,omitempty"`
}

// IterationSpec is the union type of the derive_params "iterations" field: either an
// explicit positive Count, or Auto (the JSON string "auto"). The zero value (neither
// set) means "absent" — the caller uses the default count. Auto and an explicit
// Count are mutually exclusive; UnmarshalJSON sets exactly one.
type IterationSpec struct {
	// Auto is true when the policy requested the "auto" candidate-list mode.
	Auto bool
	// Count is the explicit iteration count when Auto is false and it was specified.
	Count int
	// present records whether the field was in the JSON at all (UnmarshalJSON only
	// runs when present), distinguishing an explicit 0 — which validation must
	// reject — from an absent field, which resolves to the default count.
	present bool
}

// UnmarshalJSON decodes the iterations union: a JSON number becomes Count; the JSON
// string "auto" (case-sensitive) sets Auto; anything else (other strings, bools,
// objects, arrays, a quoted number) is a fail-closed error. It does not range-check
// Count — that is validateSEDCredential's job, so the error names the field context.
func (s *IterationSpec) UnmarshalJSON(b []byte) error {
	s.present = true
	// A JSON string (starts with '"') is only ever the literal "auto"; a quoted
	// number like "500000" must be rejected, not silently coerced to a count.
	if len(b) > 0 && b[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return fmt.Errorf("iterations string: %w", err)
		}
		if str != "auto" {
			return fmt.Errorf(`iterations string must be "auto", got %q`, str)
		}
		s.Auto, s.Count = true, 0
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New(`iterations must be a positive integer or the string "auto"`)
	}
	i, err := n.Int64()
	if err != nil {
		return fmt.Errorf("iterations must be an integer: %w", err)
	}
	s.Auto, s.Count = false, int(i)
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
	// SEDCredential states where the unlock credential comes from and how it is
	// derived (ADR-0011). It is REQUIRED when sed_unlock is "required" and MUST be
	// absent when "none". The boot path consumes and zeroizes any embedded PIN.
	SEDCredential *Credential `json:"sed_credential"`
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
	if err := validateSEDCredential(&p); err != nil {
		return nil, err
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

// validateSEDCredential enforces the ADR-0011 credential schema, fail closed:
// "required" demands a well-formed sed_credential; "none" forbids one entirely
// (mirroring ADR-0009's "none must not embed a stray credential"). It normalizes
// an absent derive to raw. The source is the policy's single credential source —
// there is no fallback chain (ADR-0011 §5).
func validateSEDCredential(p *Policy) error {
	if p.SEDUnlock == SEDUnlockNone {
		if p.SEDCredential != nil {
			return errors.New("sed_credential set but sed_unlock is none")
		}
		return nil
	}
	// SEDUnlockRequired (incl. the normalized default): a credential is mandatory.
	c := p.SEDCredential
	if c == nil {
		return errors.New("sed_unlock is required but sed_credential is absent")
	}
	switch c.Source {
	case CredentialPolicyPIN:
		if len(c.PIN) == 0 {
			return errors.New("sed_credential source policy-pin requires a non-empty pin")
		}
		if c.Path != "" {
			return errors.New("sed_credential source policy-pin must not carry a path")
		}
	case CredentialConsole:
		// No compiled-in secret for an interactive source: a stray pin here is a
		// misconfiguration (dead secret baked into the image). A path is unused by
		// console, so a stray one is likewise a misconfiguration — reject it (the
		// key fields are per-source; only keyfile takes a path).
		if len(c.PIN) != 0 {
			return errors.New("sed_credential source console must not carry a pin")
		}
		if c.Path != "" {
			return errors.New("sed_credential source console must not carry a path")
		}
	case CredentialKeyFile:
		// The keyfile source needs a path to read the key from and stores no
		// compiled-in secret: a path is mandatory and a stray pin is a
		// misconfiguration (a dead secret baked into the image).
		if c.Path == "" {
			return errors.New("sed_credential source keyfile requires a non-empty path")
		}
		if len(c.PIN) != 0 {
			return errors.New("sed_credential source keyfile must not carry a pin")
		}
	default:
		return fmt.Errorf("unknown sed_credential source %q", c.Source)
	}
	switch c.Derive {
	case "":
		c.Derive = DeriveRaw // absence = raw: today's behavior
	case DeriveRaw, DeriveSedutilPBKDF2:
	default:
		return fmt.Errorf("unknown sed_credential derive %q", c.Derive)
	}
	// derive_params (#112) is only meaningful for sedutil-pbkdf2; a stray one on any
	// other derive is a misconfiguration (dead knob), rejected fail-closed like the
	// per-source stray-field rules above.
	if c.DeriveParams != nil {
		if c.Derive != DeriveSedutilPBKDF2 {
			return fmt.Errorf("sed_credential derive_params is only valid with derive %q", DeriveSedutilPBKDF2)
		}
		dp := c.DeriveParams
		if dp.Iterations.present && !dp.Iterations.Auto {
			// An absent iterations field means the default; an explicit count must be
			// positive and within a sane bound (an explicit 0 or negative is rejected).
			if dp.Iterations.Count <= 0 || dp.Iterations.Count > maxSedutilPBKDF2Iterations {
				return fmt.Errorf("sed_credential derive_params iterations %d out of range (1..%d)", dp.Iterations.Count, maxSedutilPBKDF2Iterations)
			}
		}
		// key_len: absent (zero) means the default; an explicit value is bound-checked.
		if dp.KeyLen != 0 && (dp.KeyLen < 1 || dp.KeyLen > maxSedutilPBKDF2KeyLen) {
			return fmt.Errorf("sed_credential derive_params key_len %d out of range (1..%d)", dp.KeyLen, maxSedutilPBKDF2KeyLen)
		}
	}
	return nil
}

// ResolvedKeyLen returns the sedutil-pbkdf2 derived-key length to use: the explicit
// derive_params key_len, or the default when unset. Parse bound-checks any explicit
// value, so this returns a validated length.
func (c *Credential) ResolvedKeyLen() int {
	if c.DeriveParams != nil && c.DeriveParams.KeyLen != 0 {
		return c.DeriveParams.KeyLen
	}
	return defaultSedutilPBKDF2KeyLen
}

// ResolvedIterations returns the sedutil-pbkdf2 iteration count to use and whether
// the policy requested "auto" mode. When auto is false, count is the explicit
// derive_params value or the default when unset (Parse validates any explicit
// value). When auto is true, count is 0 (the caller iterates its candidate list).
func (c *Credential) ResolvedIterations() (count int, auto bool) {
	if c.DeriveParams == nil {
		return defaultSedutilPBKDF2Iterations, false
	}
	if c.DeriveParams.Iterations.Auto {
		return 0, true
	}
	if c.DeriveParams.Iterations.Count != 0 {
		return c.DeriveParams.Iterations.Count, false
	}
	return defaultSedutilPBKDF2Iterations, false
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
	if p.SEDCredential != nil && p.SEDCredential.Source == CredentialPolicyPIN {
		errs = append(errs, errors.New(`sed_credential source must not be "policy-pin" (the compiled-in PIN is a debug source, extractable from the signed image — ADR-0011 §5)`))
	}
	for _, e := range p.Entries {
		if isTestFixturePath(e.Path) {
			errs = append(errs, fmt.Errorf("entry %q targets test-fixture path %q — not for a release build", e.Name, e.Path))
		}
	}
	return errors.Join(errs...)
}

// isTestFixturePath reports whether an ESP-relative path resolves to the
// virtual-test boot fixture (EFI/TEST/...), which must never be a release boot
// target. It normalizes the path the way the boot loader would resolve it — the
// go-boot ESP filesystem maps "/"→"\" for EFI_FILE_PROTOCOL.Open and does not
// clean the name — so separator, ".", "//", and leading-slash variants
// (e.g. `.\EFI\\TEST\`, `/EFI/TEST/`) cannot slip the fixture past the gate.
func isTestFixturePath(p string) bool {
	clean := path.Clean("/" + strings.ReplaceAll(p, `\`, "/")) // abs form; collapses ., .., //
	return strings.HasPrefix(strings.ToUpper(clean), "/EFI/TEST/")
}
