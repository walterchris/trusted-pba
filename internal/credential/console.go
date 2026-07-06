package credential

import "errors"

// maxConsoleAttempts bounds interactive retries: the console source reprompts on
// empty input at most this many times, then fails closed (ADR-0011 §5 — never an
// unbounded prompt loop or brute-force oracle). It only counts empty entries; a
// non-empty passphrase is accepted immediately, and any prompter error aborts.
const maxConsoleAttempts = 3

// errConsoleUnavailable is returned when no console capability is present.
var errConsoleUnavailable = errors.New("no console available for interactive passphrase entry")

// errConsoleEmpty is returned when the operator submitted only empty passphrases
// up to the attempt budget. It never carries any entered bytes.
var errConsoleEmpty = errors.New("no passphrase entered")

// console is the interactive-passphrase Source (ADR-0011 §4): it prompts the
// operator at the pre-boot console and returns the typed bytes as the unlock
// seed. No secret is stored at rest. It fails closed on an absent console, a
// prompter error, or exhausted empty-input retries, and zeroizes every attempt
// buffer it holds on all paths — including the error paths (#101 carry-over,
// ADR-0011 §5).
type console struct{}

// NewConsole returns the interactive-passphrase Source. It carries no secret; the
// passphrase is read on Resolve via env.Console and handed to the caller to
// zeroize.
func NewConsole() Source { return console{} }

// Resolve prompts for the passphrase via env.Console and returns the entered
// bytes. It fails closed if no console is present, if the prompter errors, or if
// only empty input is given within the attempt budget. Every buffer it reads is
// zeroized before returning on the empty-retry and error paths; only the accepted
// non-empty buffer is handed to the caller (who owns and zeroizes it).
func (console) Resolve(env Env) ([]byte, error) {
	if env.Console == nil {
		return nil, errConsoleUnavailable
	}
	for attempt := 0; attempt < maxConsoleAttempts; attempt++ {
		pin, err := env.Console.Passphrase("SED passphrase: ")
		if err != nil {
			// Zeroize any partial buffer the prompter returned alongside the error
			// before failing closed — never leave secret bytes un-zeroized.
			clear(pin)
			return nil, err
		}
		if len(pin) == 0 {
			// Empty input: reprompt within the budget. Nothing secret to clear (the
			// slice is empty), but clear defensively for uniformity.
			clear(pin)
			continue
		}
		return pin, nil
	}
	return nil, errConsoleEmpty
}

// Kind returns "console". It never returns the secret.
func (console) Kind() string { return "console" }
