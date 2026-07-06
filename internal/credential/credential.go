// Package credential is the SED unlock credential-source abstraction (ADR-0011
// §1). A Source produces the raw Admin1 PIN bytes the Opal layer needs, so the
// boot path can obtain the credential without knowing where it came from
// (compiled-in PIN today; console/keyfile/TPM later). It has no build tags and
// no UEFI/Opal dependency, so every source is host-unit-testable — credential
// sourcing must not mix into Opal protocol code (CLAUDE.md layering).
package credential

import "io/fs"

// Source resolves the raw Admin1 PIN for the SED unlock. It fails closed: any
// failure to produce the credential returns an error and no bytes — a Source
// performs no fallback and no retry beyond its own bounded policy (ADR-0011 §5).
// The caller consumes and zeroizes the returned slice.
type Source interface {
	// Resolve returns the raw Admin1 PIN bytes or fails closed with an error.
	// The caller takes ownership of the returned slice and zeroizes it after
	// use. env exposes the platform capabilities a Source may need (see Env);
	// the policy-pin source needs none.
	Resolve(env Env) ([]byte, error)
	// Kind returns a short, stable name for the source (e.g. "policy-pin") for
	// logging and error context. It MUST NEVER return the secret.
	Kind() string
}

// Prompter reads a secret passphrase from the operator without echoing it. It is
// the console capability a Source may need; it is defined here (where the console
// source consumes it) so the credential package stays UEFI-free and host-mockable
// — the tamago entrypoint supplies the real UEFI text-input implementation, host
// tests inject a mock.
type Prompter interface {
	// Passphrase displays prompt, reads a line of input without echoing the
	// secret, and returns the entered bytes (empty on an empty line). The caller
	// takes ownership of the returned slice and zeroizes it. It returns an error
	// if the input device fails; it never returns the secret in the error.
	Passphrase(prompt string) ([]byte, error)
}

// Env is the platform-capability bundle a Source may need to resolve a
// credential (e.g. prompt on the console, read the TPM, reach the network). Each
// field is nil when the platform does not provide that capability; a Source that
// needs an absent capability fails closed. It grows one field per source as later
// tickets add sources that need a capability — adding a field is
// backward-compatible, so the env parameter stays on the Source interface. See
// ADR-0011 §1.
type Env struct {
	// Console reads an interactive passphrase; nil when no text-input console is
	// available. The console source fails closed when it is nil.
	Console Prompter
	// Files is the boot volume / ESP filesystem a Source may read a keyfile from;
	// nil when no filesystem capability is available. It is the stdlib io/fs seam
	// (the tamago entrypoint wires the UEFI ESP root, which is an fs.FS; host tests
	// inject an fstest.MapFS), so the keyfile source stays UEFI-free. The keyfile
	// source fails closed when it is nil.
	Files fs.FS
}
