package credential

// policyPIN is the compiled-in-PIN Source (ADR-0009 MVP, ADR-0011 §4 debug
// source). It carries the Admin1 PIN bytes taken from the policy and hands them
// to the caller on Resolve, transferring ownership so the caller zeroizes them
// exactly once. It never stringifies or logs the PIN.
type policyPIN struct {
	pin []byte
}

// NewPolicyPIN returns a Source over the given compiled-in PIN bytes. It takes
// ownership of pin (no copy): the source holds the caller's slice until Resolve
// hands it back, so there is no extra copy to zeroize.
func NewPolicyPIN(pin []byte) Source {
	return &policyPIN{pin: pin}
}

// Resolve returns the compiled-in PIN bytes and releases the source's hold on
// them (transferring ownership to the caller to zeroize). It does not retain
// its own copy after returning, so the caller's single zeroization is complete.
func (p *policyPIN) Resolve(_ Env) ([]byte, error) {
	pin := p.pin
	p.pin = nil // do not retain the credential after handing it over
	return pin, nil
}

// Kind returns "policy-pin". It never returns the secret.
func (*policyPIN) Kind() string { return "policy-pin" }

// String implements fmt.Stringer and always returns "policy-pin{[redacted]}",
// so any %v/%s of the source (or a struct containing it) cannot leak the PIN —
// mirroring policy.PIN's structural redaction (CLAUDE.md: never log PINs).
func (*policyPIN) String() string { return "policy-pin{[redacted]}" }
