//go:build !tamago

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/walterchris/trusted-pba/internal/credential"
	"github.com/walterchris/trusted-pba/internal/opal"
	"github.com/walterchris/trusted-pba/internal/policy"
	"github.com/walterchris/trusted-pba/internal/transport"
)

// testPIN is the shared-spec Admin1 test credential (test/fixtures/opal).
const testPIN = "correct horse"

func requiredPolicy(pin string) *policy.Policy {
	return &policy.Policy{
		SEDUnlock:     policy.SEDUnlockRequired,
		SEDCredential: &policy.Credential{Source: policy.CredentialPolicyPIN, PIN: policy.PIN(pin), Derive: policy.DeriveRaw},
	}
}

// mockConstructor returns a transports constructor serving the given MockTPer (as
// the sole Storage Security device) and a counter of how often it was invoked.
func mockConstructor(m *opal.MockTPer) (func() ([]opal.Transport, error), *int) {
	calls := 0
	return func() ([]opal.Transport, error) {
		calls++
		return []opal.Transport{m}, nil
	}, &calls
}

func TestUnlockSEDNoneSkipsLoudly(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	pol := &policy.Policy{SEDUnlock: policy.SEDUnlockNone}

	construct := func() ([]opal.Transport, error) {
		t.Fatal("sed_unlock none must not construct a transport")
		return nil, nil
	}
	if err := unlockSED(pol, credential.Env{}, construct, &buf); err != nil {
		t.Fatalf("unlockSED: %v", err)
	}
	// Skipping must be loud: an explicit policy statement, never silent.
	if !strings.Contains(buf.String(), "TRUSTED-PBA: sed unlock not required by policy") {
		t.Errorf("missing loud skip marker; output: %q", buf.String())
	}
}

func TestUnlockSEDRequiredHappyPath(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := opal.NewMockTPer([]byte(testPIN))
	pol := requiredPolicy(testPIN)
	pinBacking := []byte(pol.SEDCredential.PIN) // same backing array, not a copy

	construct, calls := mockConstructor(m)
	if err := unlockSED(pol, credential.Env{}, construct, &buf); err != nil {
		t.Fatalf("unlockSED: %v", err)
	}
	if m.Locked() || !m.MBRDone() {
		t.Errorf("drive locked=%v mbrDone=%v, want unlocked with MBRDone", m.Locked(), m.MBRDone())
	}
	if !strings.Contains(buf.String(), "TRUSTED-PBA: sed unlock ok") {
		t.Errorf("missing success marker; output: %q", buf.String())
	}
	if *calls != 1 {
		t.Errorf("transport constructed %d times, want exactly 1 (no retries)", *calls)
	}
	assertPINConsumed(t, pol, pinBacking)
}

func TestUnlockSEDFailsClosedOnWrongPIN(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := opal.NewMockTPer([]byte(testPIN))
	pol := requiredPolicy("wrong pin")
	pinBacking := []byte(pol.SEDCredential.PIN)

	construct, calls := mockConstructor(m)
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if err == nil {
		t.Fatal("unlockSED with wrong PIN: want error, got nil")
	}
	if !strings.Contains(err.Error(), "sed unlock failed") {
		t.Errorf("error %q must carry the 'sed unlock failed' stage marker", err)
	}
	if strings.Contains(err.Error(), "wrong pin") || strings.Contains(buf.String(), "wrong pin") {
		t.Errorf("PIN leaked into error/output")
	}
	if !m.Locked() {
		t.Error("drive must stay locked after failed auth")
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker on failure; output: %q", buf.String())
	}
	if *calls != 1 {
		t.Errorf("transport constructed %d times, want exactly 1 (no retry into boot)", *calls)
	}
	assertPINConsumed(t, pol, pinBacking)
}

func TestUnlockSEDFailsClosedOnTransportFault(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := opal.NewMockTPer([]byte(testPIN))
	m.Inject(opal.FaultTimeout)
	pol := requiredPolicy(testPIN)
	pinBacking := []byte(pol.SEDCredential.PIN)

	construct, _ := mockConstructor(m)
	if err := unlockSED(pol, credential.Env{}, construct, &buf); err == nil {
		t.Fatal("unlockSED with transport fault: want error, got nil")
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker on failure; output: %q", buf.String())
	}
	assertPINConsumed(t, pol, pinBacking)
}

// TestUnlockSEDFailsClosedOnPartialUnlock drives the genuine partial-unlock
// state (#51 item 2): the session and the GlobalRange Set succeed — the drive
// really unlocks — then the MBRDone Set fails. The wiring must surface a hard
// error (the caller's on-error action then terminates the boot), never the
// success marker, and the PIN must still be consumed.
func TestUnlockSEDFailsClosedOnPartialUnlock(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := opal.NewMockTPer([]byte(testPIN))
	m.Inject(opal.FaultMBRDone)
	pol := requiredPolicy(testPIN)
	pinBacking := []byte(pol.SEDCredential.PIN)

	construct, _ := mockConstructor(m)
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if err == nil {
		t.Fatal("unlockSED with failed MBRDone: want error, got nil")
	}
	if !strings.Contains(err.Error(), "sed unlock failed") {
		t.Errorf("error %q must carry the 'sed unlock failed' stage marker", err)
	}
	// The mock must end in the real partial-unlock state: range unlocked, MBR
	// not done. Anything else means the fault did not model a partial unlock.
	if m.Locked() || m.MBRDone() {
		t.Errorf("drive locked=%v mbrDone=%v, want the partial-unlock state (unlocked, MBRDone unset)", m.Locked(), m.MBRDone())
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker on partial unlock; output: %q", buf.String())
	}
	assertPINConsumed(t, pol, pinBacking)
}

// TestUnlockSEDFailsClosedWithoutCarrier exercises the real fail-closed
// construction path: required + no Storage Security transport (the host stub,
// standing in for "no SSC device found") must be a hard error — never a skip.
// The PIN must be zeroized even though Unlock never ran.
func TestUnlockSEDFailsClosedWithoutCarrier(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	pol := requiredPolicy(testPIN)
	pinBacking := []byte(pol.SEDCredential.PIN)

	construct := func() ([]opal.Transport, error) {
		_, err := transport.NewAll()
		return nil, err
	}
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if !errors.Is(err, transport.ErrUnavailable) {
		t.Fatalf("want transport.ErrUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "sed unlock failed") {
		t.Errorf("error %q must carry the 'sed unlock failed' stage marker", err)
	}
	assertPINConsumed(t, pol, pinBacking)
}

// TestUnlockSEDSelectsResponsiveSED proves selectSED skips a Storage Security
// carrier that does not answer Level-0 Discovery (a non-Opal NVMe drive on a
// multi-drive machine) and authenticates the one that does — and that the PIN is
// spent on the selected SED, not the dead carrier.
func TestUnlockSEDSelectsResponsiveSED(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	dead := opal.NewMockTPer([]byte(testPIN))
	dead.Inject(opal.FaultTimeout) // Discovery fails -> must be skipped
	sed := opal.NewMockTPer([]byte(testPIN))
	pol := requiredPolicy(testPIN)
	pinBacking := []byte(pol.SEDCredential.PIN)

	construct := func() ([]opal.Transport, error) { return []opal.Transport{dead, sed}, nil }
	if err := unlockSED(pol, credential.Env{}, construct, &buf); err != nil {
		t.Fatalf("unlockSED: %v", err)
	}
	if sed.Locked() || !sed.MBRDone() {
		t.Errorf("selected SED not unlocked: locked=%v mbrDone=%v", sed.Locked(), sed.MBRDone())
	}
	if !dead.Locked() {
		t.Error("non-responsive carrier must be left untouched (locked)")
	}
	if !strings.Contains(buf.String(), "TRUSTED-PBA: sed unlock ok") {
		t.Errorf("missing success marker; output: %q", buf.String())
	}
	assertPINConsumed(t, pol, pinBacking)
}

// TestUnlockSEDNoResponsiveSEDFailsClosed proves the fail-closed selection path:
// when no carrier answers Discovery (none is an Opal SED), unlockSED returns a
// hard error, unlocks nothing, and still consumes the PIN.
func TestUnlockSEDNoResponsiveSEDFailsClosed(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	d1 := opal.NewMockTPer([]byte(testPIN))
	d1.Inject(opal.FaultTimeout)
	d2 := opal.NewMockTPer([]byte(testPIN))
	d2.Inject(opal.FaultTimeout)
	pol := requiredPolicy(testPIN)
	pinBacking := []byte(pol.SEDCredential.PIN)

	construct := func() ([]opal.Transport, error) { return []opal.Transport{d1, d2}, nil }
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if err == nil {
		t.Fatal("want error when no carrier is an Opal SED, got nil")
	}
	if !strings.Contains(err.Error(), "sed unlock failed") || !strings.Contains(err.Error(), "no locked Opal SED") {
		t.Errorf("error %q must carry the stage marker and name the no-SED condition", err)
	}
	if d1.MBRDone() || d2.MBRDone() || !d1.Locked() || !d2.Locked() {
		t.Error("no carrier may be unlocked when none is an SED")
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit success marker; output: %q", buf.String())
	}
	assertPINConsumed(t, pol, pinBacking)
}

// TestUnlockSEDSkipsNonTargetOpalDrive is the regression test for the wrong-drive
// bug (#79): a machine can expose several Opal-capable NVMe drives. selectSED must
// skip a non-locked Opal drive (e.g. a blank SSD) and unlock the locked SED — not
// just grab the first drive that answers Discovery.
func TestUnlockSEDSkipsNonTargetOpalDrive(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	decoy := opal.NewMockTPer([]byte(testPIN)) // Opal-capable but not locked (blank SSD)
	decoy.SetLockState(false, false)
	sed := opal.NewMockTPer([]byte(testPIN)) // the locked SED (default lock state)
	pol := requiredPolicy(testPIN)
	pinBacking := []byte(pol.SEDCredential.PIN)

	// decoy is enumerated first — the old "first Opal responder" logic picked it.
	construct := func() ([]opal.Transport, error) { return []opal.Transport{decoy, sed}, nil }
	if err := unlockSED(pol, credential.Env{}, construct, &buf); err != nil {
		t.Fatalf("unlockSED: %v", err)
	}
	if sed.Locked() || !sed.MBRDone() {
		t.Errorf("locked SED not unlocked: locked=%v mbrDone=%v", sed.Locked(), sed.MBRDone())
	}
	if decoy.MBRDone() {
		t.Error("non-target Opal drive must not be touched")
	}
	if !strings.Contains(buf.String(), "TRUSTED-PBA: sed unlock ok") {
		t.Errorf("missing success marker; output: %q", buf.String())
	}
	assertPINConsumed(t, pol, pinBacking)
}

// errResolve is the sentinel a failing credential source returns.
var errResolve = errors.New("resolve failed")

// failingSource is a credential.Source whose Resolve fails closed. It models the
// interactive/token sources ADR-0011 adds (console cancelled, keyfile missing,
// TPM absent). It zeroizes the PIN it was handed so the wiring's ownership
// contract (source owns pin until Resolve) still holds on the error path.
type failingSource struct{ pin []byte }

func (s *failingSource) Resolve(credential.Env) ([]byte, error) {
	clear(s.pin)
	return nil, errResolve
}
func (*failingSource) Kind() string { return "test-failing" }

// TestUnlockSEDFailsClosedOnResolveError proves the credential-source
// fail-closed path (ADR-0011 §5): when Resolve errors, unlockSED returns a hard
// error, never constructs a transport (no chainload, no retry into boot), and
// the error names the failing stage and source kind without leaking the PIN.
func TestUnlockSEDFailsClosedOnResolveError(t *testing.T) {
	// Not parallel: it swaps the package-level newCredentialSource, which the
	// other (parallel) unlockSED tests read.
	var buf bytes.Buffer
	pol := requiredPolicy(testPIN)
	pinBacking := []byte(pol.SEDCredential.PIN)

	orig := newCredentialSource
	t.Cleanup(func() { newCredentialSource = orig })
	newCredentialSource = func(cred *policy.Credential) (credential.Source, error) {
		return &failingSource{pin: []byte(cred.PIN)}, nil
	}

	construct := func() ([]opal.Transport, error) {
		t.Fatal("resolve failure must not construct a transport")
		return nil, nil
	}
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if !errors.Is(err, errResolve) {
		t.Fatalf("want wrapped resolve error, got %v", err)
	}
	if !strings.Contains(err.Error(), "sed unlock failed") || !strings.Contains(err.Error(), "test-failing") {
		t.Errorf("error %q must carry the stage marker and the source kind", err)
	}
	if strings.Contains(err.Error(), testPIN) || strings.Contains(buf.String(), testPIN) {
		t.Errorf("PIN leaked into error/output")
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker on resolve failure; output: %q", buf.String())
	}
	assertPINConsumed(t, pol, pinBacking)
}

// consolePolicy is a required policy whose credential source is the interactive
// console (no compiled-in PIN), with the given derive.
func consolePolicy(derive policy.Derive) *policy.Policy {
	return &policy.Policy{
		SEDUnlock:     policy.SEDUnlockRequired,
		SEDCredential: &policy.Credential{Source: policy.CredentialConsole, Derive: derive},
	}
}

// stringPrompter is a Prompter that returns a fixed passphrase once.
type stringPrompter struct {
	pass  string
	calls int
}

func (p *stringPrompter) Passphrase(string) ([]byte, error) {
	p.calls++
	return []byte(p.pass), nil
}

// TestUnlockSEDConsoleSourceUnlocks proves the console source is selected from
// the policy, threaded the env's Prompter, and drives the same unlock as the
// policy-pin path (the resolved passphrase is the raw credential).
func TestUnlockSEDConsoleSourceUnlocks(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := opal.NewMockTPer([]byte(testPIN))
	pol := consolePolicy(policy.DeriveRaw)
	prompter := &stringPrompter{pass: testPIN}

	construct, _ := mockConstructor(m)
	if err := unlockSED(pol, credential.Env{Console: prompter}, construct, &buf); err != nil {
		t.Fatalf("unlockSED: %v", err)
	}
	if m.Locked() || !m.MBRDone() {
		t.Errorf("drive locked=%v mbrDone=%v, want unlocked with MBRDone", m.Locked(), m.MBRDone())
	}
	if prompter.calls != 1 {
		t.Errorf("prompter called %d times, want 1", prompter.calls)
	}
	if !strings.Contains(buf.String(), "TRUSTED-PBA: sed unlock ok") {
		t.Errorf("missing success marker; output: %q", buf.String())
	}
}

// TestUnlockSEDConsoleFailsClosedWithoutConsole proves the console source fails
// closed when the platform provides no console (nil Prompter), never constructs
// a transport, and never emits the success marker.
func TestUnlockSEDConsoleFailsClosedWithoutConsole(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	pol := consolePolicy(policy.DeriveRaw)

	construct := func() ([]opal.Transport, error) {
		t.Fatal("absent console must not construct a transport")
		return nil, nil
	}
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if err == nil {
		t.Fatal("console source with no console: want error, got nil")
	}
	if !strings.Contains(err.Error(), "sed unlock failed") || !strings.Contains(err.Error(), "console") {
		t.Errorf("error %q must carry the stage marker and the source kind", err)
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker; output: %q", buf.String())
	}
}

// TestUnlockSEDDeriveNotImplementedFailsClosed proves the sedutil-pbkdf2 derive
// stage (A4, #104) fails closed at unlock time: the seed is resolved but the
// derive is not implemented, so no credential reaches the drive and no success
// marker is emitted. The PIN backing is still zeroized.
func TestUnlockSEDDeriveNotImplementedFailsClosed(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	pol := requiredPolicy(testPIN)
	pol.SEDCredential.Derive = policy.DeriveSedutilPBKDF2
	pinBacking := []byte(pol.SEDCredential.PIN)

	construct := func() ([]opal.Transport, error) {
		t.Fatal("unimplemented derive must not construct a transport")
		return nil, nil
	}
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if err == nil {
		t.Fatal("sedutil-pbkdf2 derive: want error, got nil")
	}
	if !strings.Contains(err.Error(), "sed unlock failed") || !strings.Contains(err.Error(), "derive") {
		t.Errorf("error %q must carry the stage marker and name the derive stage", err)
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker; output: %q", buf.String())
	}
	assertPINConsumed(t, pol, pinBacking)
}

// assertPINConsumed asserts the wiring's PIN contract: the policy no longer
// holds the credential and the original backing bytes are zeroized — on success
// and on every failure path.
func assertPINConsumed(t *testing.T, pol *policy.Policy, backing []byte) {
	t.Helper()
	if pol.SEDCredential != nil && pol.SEDCredential.PIN != nil {
		t.Error("policy SEDCredential.PIN must be cleared after unlockSED")
	}
	for i, b := range backing {
		if b != 0 {
			t.Errorf("PIN backing array not zeroized at byte %d", i)
			return
		}
	}
}
