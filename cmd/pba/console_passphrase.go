package main

// maxPassphraseLen bounds a single console passphrase entry so a stuck or
// adversarial input stream cannot grow the buffer unbounded. It is a length cap
// on the input line, not a retry cap (the credential.console source bounds
// retries, ADR-0011 §5).
const maxPassphraseLen = 128

// newPassphraseBuf returns the accumulator the console prompter reads a
// passphrase into, pre-allocated to the hard line-length cap so append never
// reallocates. That is a secret-hygiene requirement, not an optimization:
// growing from a nil/short slice would strand un-scrubbed passphrase-prefix
// copies (at capacities 1, 2, 4, …) in pre-boot heap that survive to the OS,
// because the prompter's clear() can only zeroize the final backing array
// (#124, R-003). One array holds every possible passphrase, so one clear()
// scrubs all of it. Defined in a build-tag-free file so the host test can pin
// the no-reallocation invariant without the tamago-only UEFI prompter, the same
// way the opal layer pins its grow-budget reservation.
func newPassphraseBuf() []byte { return make([]byte, 0, maxPassphraseLen) }
