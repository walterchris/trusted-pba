//go:build !tamago

package main

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

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

// TestUnlockSEDSedutilPBKDF2FailsClosedWithoutSerial proves the sedutil-pbkdf2
// derive stage (A4a, #104) fails closed at unlock time with today's carrier: the
// seed is resolved and the locked SED is selected, but the selected transport does
// not implement credential.Serialer (the Storage-Security carrier; the real serial
// arrives with the NVMe-passthru carrier, A4b). The derive therefore aborts with
// the "serial unavailable" error, no credential reaches the drive, no success
// marker is emitted, and the seed backing is still zeroized. The SED stays locked.
func TestUnlockSEDSedutilPBKDF2FailsClosedWithoutSerial(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := opal.NewMockTPer([]byte(testPIN)) // locked SED; does NOT implement Serialer
	pol := requiredPolicy(testPIN)
	pol.SEDCredential.Derive = policy.DeriveSedutilPBKDF2
	pinBacking := []byte(pol.SEDCredential.PIN)

	construct, _ := mockConstructor(m)
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if err == nil {
		t.Fatal("sedutil-pbkdf2 derive without serial: want error, got nil")
	}
	if !strings.Contains(err.Error(), "sed unlock failed") || !strings.Contains(err.Error(), "derive") {
		t.Errorf("error %q must carry the stage marker and name the derive stage", err)
	}
	if !strings.Contains(err.Error(), "NVMe-passthru carrier (A4b)") {
		t.Errorf("error %q must name the missing serial capability (A4b)", err)
	}
	if !m.Locked() {
		t.Error("drive must stay locked when the derive fails closed")
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker; output: %q", buf.String())
	}
	assertPINConsumed(t, pol, pinBacking)
}

// serialMockTPer is a MockTPer that also implements credential.Serialer, modelling
// the A4b NVMe-passthru carrier: it answers Level-0 Discovery like the SED and
// supplies a fixed drive serial as the PBKDF2 salt.
type serialMockTPer struct {
	*opal.MockTPer
	serial    []byte
	serialErr error // when set, Serial fails closed (models a carrier read error)
}

func (m *serialMockTPer) Serial() ([]byte, error) {
	if m.serialErr != nil {
		return nil, m.serialErr
	}
	return m.serial, nil
}

// pbkdf2Serial is a fixed 20-byte space-padded serial (the PBKDF2 salt).
var pbkdf2Serial = []byte("S3EMNX0M12345678    ")

// pbkdf2Iterations / pbkdf2KeyLen are the default sedutil-pbkdf2 parameters the
// derive-path tests exercise (the resolved defaults for a policy with no
// derive_params).
const (
	pbkdf2Iterations = credential.SedutilPBKDF2Iterations
	pbkdf2KeyLen     = credential.SedutilPBKDF2KeyLen
)

// TestApplyDeriveSedutilPBKDF2NewBuffer proves applyDerive returns the
// PBKDF2-HMAC-SHA512 key (matching credential.SedutilPBKDF2) in a NEW buffer
// distinct from the seed. Zeroizing the seed is now the caller's job (unlockSED),
// so the seed is left intact here.
func TestApplyDeriveSedutilPBKDF2NewBuffer(t *testing.T) {
	t.Parallel()
	seed := []byte(testPIN)
	want, err := credential.SedutilPBKDF2([]byte(testPIN), pbkdf2Serial, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		t.Fatalf("reference derive: %v", err)
	}

	got, err := applyDeriveImpl(seed, pbkdf2Serial, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		t.Fatalf("applyDerive: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("derived key = %x, want %x", got, want)
	}
	if &got[0] == &seed[0] {
		t.Error("derived key must be a NEW buffer, not the seed backing")
	}
}

// TestUnlockSEDSedutilPBKDF2ZeroizesSeedAndDerived proves the full sedutil-pbkdf2
// unlock path (A4a happy path via an A4b-like Serialer carrier) scrubs BOTH the
// resolved seed and the derived key after unlockSED. It seeds the mock SED with the
// derived credential so Unlock succeeds, captures the derived buffer via the
// applyDerive seam, and asserts both buffers end zeroized.
func TestUnlockSEDSedutilPBKDF2ZeroizesSeedAndDerived(t *testing.T) {
	// Not parallel: swaps the package-level applyDerive seam.
	var buf bytes.Buffer
	derivedKey, err := credential.SedutilPBKDF2([]byte(testPIN), pbkdf2Serial, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		t.Fatalf("reference derive: %v", err)
	}
	m := &serialMockTPer{MockTPer: opal.NewMockTPer(derivedKey), serial: pbkdf2Serial}
	pol := requiredPolicy(testPIN)
	pol.SEDCredential.Derive = policy.DeriveSedutilPBKDF2
	seedBacking := []byte(pol.SEDCredential.PIN)

	var captured []byte
	orig := applyDerive
	t.Cleanup(func() { applyDerive = orig })
	applyDerive = func(seed, salt []byte, iterations, keyLen int) ([]byte, error) {
		out, err := orig(seed, salt, iterations, keyLen)
		captured = out // the derived buffer handed to Unlock
		return out, err
	}

	construct := func() ([]opal.Transport, error) { return []opal.Transport{m}, nil }
	if err := unlockSED(pol, credential.Env{}, construct, &buf); err != nil {
		t.Fatalf("unlockSED: %v", err)
	}
	if m.Locked() || !m.MBRDone() {
		t.Errorf("drive locked=%v mbrDone=%v, want unlocked with MBRDone", m.Locked(), m.MBRDone())
	}
	if !strings.Contains(buf.String(), "TRUSTED-PBA: sed unlock ok") {
		t.Errorf("missing success marker; output: %q", buf.String())
	}
	assertZeroized(t, seedBacking, "seed")
	if captured == nil {
		t.Fatal("derive seam did not capture the derived buffer")
	}
	assertZeroized(t, captured, "derived key")
}

// TestUnlockSEDSedutilPBKDF2ZeroizesOnUnlockFailure proves the error path also
// scrubs both buffers: the derive succeeds (Serialer present) but Unlock fails
// (wrong derived credential on the drive), and unlockSED fails closed with the seed
// and derived buffers both zeroized.
func TestUnlockSEDSedutilPBKDF2ZeroizesOnUnlockFailure(t *testing.T) {
	// Not parallel: swaps the package-level applyDerive seam.
	var buf bytes.Buffer
	// Seed the drive with a DIFFERENT credential so the derived key does not match.
	m := &serialMockTPer{MockTPer: opal.NewMockTPer([]byte("not the derived key")), serial: pbkdf2Serial}
	pol := requiredPolicy(testPIN)
	pol.SEDCredential.Derive = policy.DeriveSedutilPBKDF2
	seedBacking := []byte(pol.SEDCredential.PIN)

	var captured []byte
	orig := applyDerive
	t.Cleanup(func() { applyDerive = orig })
	applyDerive = func(seed, salt []byte, iterations, keyLen int) ([]byte, error) {
		out, err := orig(seed, salt, iterations, keyLen)
		captured = out
		return out, err
	}

	construct := func() ([]opal.Transport, error) { return []opal.Transport{m}, nil }
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if err == nil {
		t.Fatal("wrong derived credential: want error, got nil")
	}
	if !m.Locked() {
		t.Error("drive must stay locked after failed auth")
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker on failure; output: %q", buf.String())
	}
	assertZeroized(t, seedBacking, "seed")
	if captured == nil {
		t.Fatal("derive seam did not capture the derived buffer")
	}
	assertZeroized(t, captured, "derived key")
}

// TestUnlockSEDSedutilPBKDF2FailsClosedOnSerialError proves the derive fails
// closed when the carrier implements Serialer but reading the serial errors: no
// credential reaches the drive, the SED stays locked, and the seed is scrubbed.
func TestUnlockSEDSedutilPBKDF2FailsClosedOnSerialError(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := &serialMockTPer{MockTPer: opal.NewMockTPer([]byte(testPIN)), serialErr: errors.New("serial read failed")}
	pol := requiredPolicy(testPIN)
	pol.SEDCredential.Derive = policy.DeriveSedutilPBKDF2
	seedBacking := []byte(pol.SEDCredential.PIN)

	construct := func() ([]opal.Transport, error) { return []opal.Transport{m}, nil }
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if err == nil {
		t.Fatal("serial read error: want error, got nil")
	}
	if !strings.Contains(err.Error(), "sed unlock failed") || !strings.Contains(err.Error(), "derive") {
		t.Errorf("error %q must carry the stage marker and name the derive stage", err)
	}
	if !m.Locked() {
		t.Error("drive must stay locked when the serial read fails")
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker; output: %q", buf.String())
	}
	assertZeroized(t, seedBacking, "seed")
}

// fakeUnlocker is an unlocker whose Unlock returns a configured error per attempt,
// recording each key it received (by reference, so the caller's post-Unlock
// clear() is observable) and each key's contents captured at call time (a copy, to
// prove best-first selection by which iteration count derived the accepted key). It
// does NOT zeroize the key itself — that is unlockWithDerive's job — so tests can
// assert the loop scrubs every key on every path.
type fakeUnlocker struct {
	results   []error  // result for attempt i (index into the calls)
	gotKeys   [][]byte // the key slice handed to each Unlock (same backing)
	gotCopies [][]byte // a snapshot copy of each key at call time
	calls     int
}

func (f *fakeUnlocker) Unlock(_ opal.Authority, pin []byte) error {
	i := f.calls
	f.calls++
	f.gotKeys = append(f.gotKeys, pin)
	f.gotCopies = append(f.gotCopies, bytes.Clone(pin))
	if i < len(f.results) {
		return f.results[i]
	}
	return errors.New("unexpected extra unlock attempt")
}

// autoPolicy is a required sedutil-pbkdf2 policy in "auto" iteration mode.
func autoPolicy() *policy.Credential {
	return &policy.Credential{
		Source:       policy.CredentialConsole,
		Derive:       policy.DeriveSedutilPBKDF2,
		DeriveParams: &policy.DeriveParams{Iterations: policy.IterationSpec{Auto: true}},
	}
}

// TestUnlockWithDeriveAutoSelectsBestFirst proves the auto loop tries candidates
// best-first and stops on the first that authenticates: the fake accepts the second
// candidate (75000) only, so the loop must derive at 500000 (NOT_AUTHORIZED),
// advance, then derive at 75000 (success) — exactly two attempts, the second key
// matching the 75000 KAT.
func TestUnlockWithDeriveAutoSelectsBestFirst(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	seed := []byte(testPIN)
	tr := &serialMockTPer{MockTPer: opal.NewMockTPer(nil), serial: pbkdf2Serial}
	want75000, err := credential.SedutilPBKDF2([]byte(testPIN), pbkdf2Serial, 75000, pbkdf2KeyLen)
	if err != nil {
		t.Fatalf("reference derive: %v", err)
	}
	fu := &fakeUnlocker{results: []error{opal.ErrNotAuthorized, nil}}

	if err := unlockWithDerive(fu, autoPolicy(), seed, tr, &buf); err != nil {
		t.Fatalf("unlockWithDerive auto: %v", err)
	}
	if fu.calls != 2 {
		t.Fatalf("auto made %d unlock attempts, want exactly 2 (500000 then 75000)", fu.calls)
	}
	// Attempt 1 must be the best-first (500000) key, attempt 2 the 75000 key.
	want500000, _ := credential.SedutilPBKDF2([]byte(testPIN), pbkdf2Serial, 500000, pbkdf2KeyLen)
	if !bytes.Equal(fu.gotCopies[0], want500000) {
		t.Errorf("attempt 1 key = %x, want the 500000 derivation %x", fu.gotCopies[0], want500000)
	}
	if !bytes.Equal(fu.gotCopies[1], want75000) {
		t.Errorf("attempt 2 key = %x, want the 75000 derivation %x", fu.gotCopies[1], want75000)
	}
	// Every derived key must be scrubbed by the loop on every path.
	for i, k := range fu.gotKeys {
		assertZeroized(t, k, "auto derived key attempt "+strconv.Itoa(i))
	}
	assertZeroized(t, seed, "seed")
}

// TestUnlockWithDeriveAutoExhaustionFailsClosed proves the auto loop fails closed
// after every candidate returns NOT_AUTHORIZED — it never advances into boot — and
// scrubs every derived key.
func TestUnlockWithDeriveAutoExhaustionFailsClosed(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	seed := []byte(testPIN)
	tr := &serialMockTPer{MockTPer: opal.NewMockTPer(nil), serial: pbkdf2Serial}
	fu := &fakeUnlocker{results: []error{opal.ErrNotAuthorized, opal.ErrNotAuthorized}}

	err := unlockWithDerive(fu, autoPolicy(), seed, tr, &buf)
	if err == nil {
		t.Fatal("auto with all NOT_AUTHORIZED: want error, got nil")
	}
	if !strings.Contains(err.Error(), "no candidate iteration count authenticated") {
		t.Errorf("error %q must name the exhaustion condition", err)
	}
	if fu.calls != len(sedutilPBKDF2AutoIterations) {
		t.Errorf("auto made %d attempts, want %d (the full candidate list)", fu.calls, len(sedutilPBKDF2AutoIterations))
	}
	for i, k := range fu.gotKeys {
		assertZeroized(t, k, "auto derived key attempt "+strconv.Itoa(i))
	}
	assertZeroized(t, seed, "seed")
}

// TestUnlockWithDeriveAutoStopsOnLockout proves AUTHORITY_LOCKED_OUT on the first
// candidate halts immediately (no second attempt) and fails closed — further tries
// would burn the try-limit and are futile.
func TestUnlockWithDeriveAutoStopsOnLockout(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	seed := []byte(testPIN)
	tr := &serialMockTPer{MockTPer: opal.NewMockTPer(nil), serial: pbkdf2Serial}
	fu := &fakeUnlocker{results: []error{opal.ErrAuthLockedOut}}

	err := unlockWithDerive(fu, autoPolicy(), seed, tr, &buf)
	if !errors.Is(err, opal.ErrAuthLockedOut) {
		t.Fatalf("want ErrAuthLockedOut, got %v", err)
	}
	if fu.calls != 1 {
		t.Errorf("auto made %d attempts, want exactly 1 (stop on lockout)", fu.calls)
	}
	for i, k := range fu.gotKeys {
		assertZeroized(t, k, "auto derived key attempt "+strconv.Itoa(i))
	}
	assertZeroized(t, seed, "seed")
}

// TestUnlockWithDeriveAutoStopsOnOtherError proves a non-auth error (transport,
// malformed) on the first candidate halts immediately and is not masked by advancing
// to the next candidate.
func TestUnlockWithDeriveAutoStopsOnOtherError(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	seed := []byte(testPIN)
	tr := &serialMockTPer{MockTPer: opal.NewMockTPer(nil), serial: pbkdf2Serial}
	transportErr := errors.New("transport exploded")
	fu := &fakeUnlocker{results: []error{transportErr}}

	err := unlockWithDerive(fu, autoPolicy(), seed, tr, &buf)
	if !errors.Is(err, transportErr) {
		t.Fatalf("want the transport error, got %v", err)
	}
	if fu.calls != 1 {
		t.Errorf("auto made %d attempts, want exactly 1 (stop on non-auth error)", fu.calls)
	}
	for i, k := range fu.gotKeys {
		assertZeroized(t, k, "auto derived key attempt "+strconv.Itoa(i))
	}
	assertZeroized(t, seed, "seed")
}

// TestUnlockWithDeriveExplicitSingleAttempt proves an explicit iteration count
// derives once and attempts Unlock exactly once (no auto trial loop), with the key
// zeroized afterward.
func TestUnlockWithDeriveExplicitSingleAttempt(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	seed := []byte(testPIN)
	tr := &serialMockTPer{MockTPer: opal.NewMockTPer(nil), serial: pbkdf2Serial}
	cred := &policy.Credential{
		Source:       policy.CredentialConsole,
		Derive:       policy.DeriveSedutilPBKDF2,
		DeriveParams: &policy.DeriveParams{Iterations: policy.IterationSpec{Count: 75000}},
	}
	fu := &fakeUnlocker{results: []error{nil}}

	if err := unlockWithDerive(fu, cred, seed, tr, &buf); err != nil {
		t.Fatalf("unlockWithDerive explicit: %v", err)
	}
	if fu.calls != 1 {
		t.Fatalf("explicit made %d attempts, want exactly 1", fu.calls)
	}
	want, _ := credential.SedutilPBKDF2([]byte(testPIN), pbkdf2Serial, 75000, pbkdf2KeyLen)
	if !bytes.Equal(fu.gotCopies[0], want) {
		t.Errorf("explicit key = %x, want the 75000 derivation %x", fu.gotCopies[0], want)
	}
	assertZeroized(t, fu.gotKeys[0], "explicit derived key")
	assertZeroized(t, seed, "seed")
}

// assertZeroized fails if any byte of b is non-zero.
func assertZeroized(t *testing.T, b []byte, name string) {
	t.Helper()
	for i, v := range b {
		if v != 0 {
			t.Errorf("%s buffer not zeroized at byte %d", name, i)
			return
		}
	}
}

// testKeyPath is the ESP-relative keyfile path the keyfile-source tests use.
const testKeyPath = "EFI/KEY/sed.key"

// keyfilePolicy is a required policy whose credential source is the file-backed
// keyfile at testKeyPath, with derive raw.
func keyfilePolicy() *policy.Policy {
	return &policy.Policy{
		SEDUnlock:     policy.SEDUnlockRequired,
		SEDCredential: &policy.Credential{Source: policy.CredentialKeyFile, Path: testKeyPath, Derive: policy.DeriveRaw},
	}
}

// TestUnlockSEDKeyFileSourceUnlocks proves the keyfile source is selected from the
// policy, threaded the env's Files filesystem, and drives the same unlock as the
// policy-pin path (the file's bytes are the raw credential).
func TestUnlockSEDKeyFileSourceUnlocks(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := opal.NewMockTPer([]byte(testPIN))
	pol := keyfilePolicy()
	env := credential.Env{Files: fstest.MapFS{testKeyPath: {Data: []byte(testPIN)}}}

	construct, _ := mockConstructor(m)
	if err := unlockSED(pol, env, construct, &buf); err != nil {
		t.Fatalf("unlockSED: %v", err)
	}
	if m.Locked() || !m.MBRDone() {
		t.Errorf("drive locked=%v mbrDone=%v, want unlocked with MBRDone", m.Locked(), m.MBRDone())
	}
	if !strings.Contains(buf.String(), "TRUSTED-PBA: sed unlock ok") {
		t.Errorf("missing success marker; output: %q", buf.String())
	}
}

// TestUnlockSEDKeyFileWrongContentFailsClosed proves a keyfile whose bytes are not
// the drive credential fails closed at auth: the drive stays locked, no success
// marker, and no key content leaks into the error/output.
func TestUnlockSEDKeyFileWrongContentFailsClosed(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := opal.NewMockTPer([]byte(testPIN))
	const wrong = "wrong key bytes"
	pol := keyfilePolicy()
	env := credential.Env{Files: fstest.MapFS{testKeyPath: {Data: []byte(wrong)}}}

	construct, _ := mockConstructor(m)
	err := unlockSED(pol, env, construct, &buf)
	if err == nil {
		t.Fatal("wrong-content keyfile: want error, got nil")
	}
	if !strings.Contains(err.Error(), "sed unlock failed") {
		t.Errorf("error %q must carry the 'sed unlock failed' stage marker", err)
	}
	if !m.Locked() {
		t.Error("drive must stay locked after failed auth")
	}
	if strings.Contains(err.Error(), wrong) || strings.Contains(buf.String(), wrong) {
		t.Errorf("key content leaked into error/output")
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker on failure; output: %q", buf.String())
	}
}

// TestUnlockSEDKeyFileFailsClosedWithoutFiles proves the keyfile source fails
// closed when the platform provides no filesystem (nil Files), never constructs a
// transport, and never emits the success marker.
func TestUnlockSEDKeyFileFailsClosedWithoutFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	pol := keyfilePolicy()

	construct := func() ([]opal.Transport, error) {
		t.Fatal("absent filesystem must not construct a transport")
		return nil, nil
	}
	err := unlockSED(pol, credential.Env{}, construct, &buf)
	if err == nil {
		t.Fatal("keyfile source with no filesystem: want error, got nil")
	}
	if !strings.Contains(err.Error(), "sed unlock failed") || !strings.Contains(err.Error(), "keyfile") {
		t.Errorf("error %q must carry the stage marker and the source kind", err)
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker; output: %q", buf.String())
	}
}

// TestUnlockSEDKeyFileMissingFailsClosed proves a missing keyfile fails closed
// (never falls through to an unlock attempt) and reports the failing stage.
func TestUnlockSEDKeyFileMissingFailsClosed(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	pol := keyfilePolicy()
	env := credential.Env{Files: fstest.MapFS{}} // no keyfile present

	construct := func() ([]opal.Transport, error) {
		t.Fatal("missing keyfile must not construct a transport")
		return nil, nil
	}
	err := unlockSED(pol, env, construct, &buf)
	if err == nil {
		t.Fatal("missing keyfile: want error, got nil")
	}
	if !strings.Contains(err.Error(), "sed unlock failed") || !strings.Contains(err.Error(), "keyfile") {
		t.Errorf("error %q must carry the stage marker and the source kind", err)
	}
	if strings.Contains(buf.String(), "sed unlock ok") {
		t.Errorf("must not emit the success marker; output: %q", buf.String())
	}
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

// TestResolvedDerivDefaultsMatchCredentialConstants guards the deliberate
// duplication of the sedutil-pbkdf2 defaults across packages: internal/policy
// keeps comment-linked local defaults so it need not import internal/credential
// (ADR-0004 layering). A policy with no derive_params must therefore resolve to
// exactly credential's exported defaults — enforced here via the public API so
// the two pairs cannot silently drift.
func TestResolvedDerivDefaultsMatchCredentialConstants(t *testing.T) {
	c := &policy.Credential{Source: policy.CredentialPolicyPIN, Derive: policy.DeriveSedutilPBKDF2}
	if got, auto := c.ResolvedIterations(); auto || got != credential.SedutilPBKDF2Iterations {
		t.Errorf("ResolvedIterations() = (%d, %t), want (%d, false)", got, auto, credential.SedutilPBKDF2Iterations)
	}
	if got := c.ResolvedKeyLen(); got != credential.SedutilPBKDF2KeyLen {
		t.Errorf("ResolvedKeyLen() = %d, want %d", got, credential.SedutilPBKDF2KeyLen)
	}
}
