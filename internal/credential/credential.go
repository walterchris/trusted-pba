// Package credential is the SED unlock credential-source abstraction (ADR-0011
// §1). A Source produces the raw Admin1 PIN bytes the Opal layer needs, so the
// boot path can obtain the credential without knowing where it came from
// (compiled-in PIN today; console/keyfile/TPM later). It has no build tags and
// no UEFI/Opal dependency, so every source is host-unit-testable — credential
// sourcing must not mix into Opal protocol code (CLAUDE.md layering).
package credential

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

// Env is the platform-capability bundle a Source may need to resolve a
// credential (e.g. prompt on the console, read the TPM, reach the network).
// It is intentionally empty today: the only current source (policy-pin) needs
// nothing from it. It grows one field per source as later tickets add sources
// that need a capability — adding a field is backward-compatible, so the env
// parameter stays on the Source interface now to spare those sources a
// signature change. See ADR-0011 §1.
type Env struct{}
