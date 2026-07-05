package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(`{"require_secure_boot":true,"sed_unlock":"none","entries":[{"name":"win","path":"EFI/Microsoft/Boot/bootmgfw.efi","validation":"firmware"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.RequireSecureBoot || len(p.Entries) != 1 || p.Entries[0].Validation != Firmware {
		t.Fatalf("unexpected policy: %+v", p)
	}
}

func TestParseFailsClosed(t *testing.T) {
	bad := map[string]string{
		"malformed json":     `{`,
		"empty object":       `{}`,
		"no entries":         `{"sed_unlock":"none","entries":[]}`,
		"missing path":       `{"sed_unlock":"none","entries":[{"name":"x","validation":"firmware"}]}`,
		"missing name":       `{"sed_unlock":"none","entries":[{"path":"a","validation":"pba"}]}`,
		"unknown validation": `{"sed_unlock":"none","entries":[{"name":"x","path":"a","validation":"magic"}]}`,
		"unknown field":      `{"sed_unlock":"none","entries":[{"name":"x","path":"a","validation":"pba","extra":1}]}`,
		"wrong type":         `{"require_secure_boot":"yes","entries":[]}`,
		"unknown on_error":   `{"on_error":"explode","sed_unlock":"none","entries":[{"name":"x","path":"a","validation":"pba"}]}`,
		// SED unlock gate: only the explicit values are accepted; "required"
		// (incl. absent = required) demands a PIN in the MVP policy-as-PIN-source
		// model, and "none" must not embed a stray credential.
		"unknown sed_unlock":      `{"sed_unlock":"maybe","entries":[{"name":"x","path":"a","validation":"pba"}]}`,
		"required without pin":    `{"sed_unlock":"required","entries":[{"name":"x","path":"a","validation":"pba"}]}`,
		"absent unlock means req": `{"entries":[{"name":"x","path":"a","validation":"pba"}]}`,
		"none with pin":           `{"sed_unlock":"none","sed_pin":"correct horse","entries":[{"name":"x","path":"a","validation":"pba"}]}`,
		"sed_pin wrong json type": `{"sed_unlock":"required","sed_pin":1,"entries":[{"name":"x","path":"a","validation":"pba"}]}`,
	}
	for name, in := range bad {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestParseOnError(t *testing.T) {
	// Absent on_error defaults to halt (the safest fail-closed action).
	p, err := Parse([]byte(`{"sed_unlock":"none","entries":[{"name":"x","path":"a","validation":"pba"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.OnError != OnErrorHalt {
		t.Errorf("default on_error = %q, want %q", p.OnError, OnErrorHalt)
	}

	for _, mode := range []OnError{OnErrorHalt, OnErrorShutdown, OnErrorReboot} {
		in := `{"on_error":"` + string(mode) + `","sed_unlock":"none","entries":[{"name":"x","path":"a","validation":"pba"}]}`
		got, err := Parse([]byte(in))
		if err != nil {
			t.Errorf("on_error %q: unexpected error %v", mode, err)
			continue
		}
		if got.OnError != mode {
			t.Errorf("on_error = %q, want %q", got.OnError, mode)
		}
	}
}

func TestParseSEDUnlock(t *testing.T) {
	// Explicit "required" with a PIN: the PIN bytes are carried for the boot
	// path (MVP compiled-in credential, shared-spec test value; ADR-0009).
	p, err := Parse([]byte(`{"sed_unlock":"required","sed_pin":"correct horse","entries":[{"name":"x","path":"a","validation":"pba"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.SEDUnlock != SEDUnlockRequired || string(p.SEDPIN) != "correct horse" {
		t.Errorf("got sed_unlock=%q pin len %d, want required with the test PIN", p.SEDUnlock, len(p.SEDPIN))
	}

	// Absence = required (fail closed): the value must never silently become
	// "none". With a PIN present the policy parses and is required.
	p, err = Parse([]byte(`{"sed_pin":"correct horse","entries":[{"name":"x","path":"a","validation":"pba"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.SEDUnlock != SEDUnlockRequired {
		t.Errorf("absent sed_unlock = %q, want %q (fail closed)", p.SEDUnlock, SEDUnlockRequired)
	}

	// Explicit "none" (no PIN) is the only way to skip the unlock.
	p, err = Parse([]byte(`{"sed_unlock":"none","entries":[{"name":"x","path":"a","validation":"pba"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.SEDUnlock != SEDUnlockNone || len(p.SEDPIN) != 0 {
		t.Errorf("got sed_unlock=%q pin len %d, want none without a PIN", p.SEDUnlock, len(p.SEDPIN))
	}
}

// TestPINStringRedacts pins the structural never-log-PINs guard: formatting a
// PIN must never yield the credential bytes.
func TestPINStringRedacts(t *testing.T) {
	for _, verb := range []string{"%v", "%s"} {
		if got := fmt.Sprintf(verb, PIN("x")); got != "[redacted]" {
			t.Errorf("Sprintf(%q, PIN) = %q, want %q", verb, got, "[redacted]")
		}
	}
}

func TestDefault(t *testing.T) {
	if _, err := Default(); err != nil {
		t.Fatalf("embedded default policy must parse: %v", err)
	}
}

func TestSelect(t *testing.T) {
	p := &Policy{Entries: []BootEntry{{Name: "first", Path: "a", Validation: PBA}, {Name: "second", Path: "b", Validation: Firmware}}}
	e, err := p.Select()
	if err != nil || e.Name != "first" {
		t.Fatalf("Select() = %+v, %v; want entry 'first'", e, err)
	}
	if _, err := (&Policy{}).Select(); !errors.Is(err, ErrNoEntries) {
		t.Errorf("Select() on empty policy: want ErrNoEntries, got %v", err)
	}
}

func TestCheckSecureBoot(t *testing.T) {
	cases := []struct {
		require, enforcing, wantErr bool
	}{
		{false, false, false},
		{false, true, false},
		{true, true, false},
		{true, false, true}, // require + not enforcing -> fail closed
	}
	for _, c := range cases {
		err := (&Policy{RequireSecureBoot: c.require}).CheckSecureBoot(c.enforcing)
		if (err != nil) != c.wantErr {
			t.Errorf("require=%v enforcing=%v: err=%v wantErr=%v", c.require, c.enforcing, err, c.wantErr)
		}
	}
}

// TestCheckReleaseReady covers the release gate: a production-safe policy passes,
// and each unsafe development default (Secure Boot not required — explicit false
// AND absent — sed_unlock "none", a test-fixture target) fails closed. The last
// case proves violations are reported together.
func TestCheckReleaseReady(t *testing.T) {
	prod := func() *Policy {
		return &Policy{
			RequireSecureBoot: true,
			SEDUnlock:         SEDUnlockRequired,
			SEDPIN:            PIN("x"),
			Entries:           []BootEntry{{Name: "os", Path: "EFI/Microsoft/Boot/bootmgfw.efi", Validation: Firmware}},
		}
	}
	cases := []struct {
		name    string
		mutate  func(*Policy)
		wantErr bool
	}{
		{"production-safe", func(*Policy) {}, false},
		{"secure boot not required", func(p *Policy) { p.RequireSecureBoot = false }, true},
		{"sed_unlock none", func(p *Policy) { p.SEDUnlock = SEDUnlockNone; p.SEDPIN = nil }, true},
		{"test-fixture target", func(p *Policy) { p.Entries[0].Path = "EFI/TEST/TESTAPP.EFI" }, true},
		{"test-fixture target lowercase", func(p *Policy) { p.Entries[0].Path = "efi/test/testapp.efi" }, true},
		{"test-fixture leading ./", func(p *Policy) { p.Entries[0].Path = "./EFI/TEST/TESTAPP.EFI" }, true},
		{"test-fixture leading /", func(p *Policy) { p.Entries[0].Path = "/EFI/TEST/TESTAPP.EFI" }, true},
		{"test-fixture double slash", func(p *Policy) { p.Entries[0].Path = "EFI//TEST//TESTAPP.EFI" }, true},
		{"test-fixture backslashes", func(p *Policy) { p.Entries[0].Path = `EFI\TEST\TESTAPP.EFI` }, true},
		{"pba-override to a real path is allowed", func(p *Policy) { p.Entries[0].Validation = PBAOverride }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := prod()
			c.mutate(p)
			if err := p.CheckReleaseReady(); (err != nil) != c.wantErr {
				t.Errorf("CheckReleaseReady() err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}

	// The dev default (parsed from an absent require_secure_boot) must be blocked:
	// absent -> false -> unsafe, not a silent pass.
	absent := &Policy{SEDUnlock: SEDUnlockRequired, SEDPIN: PIN("x"),
		Entries: []BootEntry{{Name: "os", Path: "EFI/BOOT/BOOTX64.EFI", Validation: Firmware}}}
	if err := absent.CheckReleaseReady(); err == nil {
		t.Error("absent require_secure_boot must be treated as unsafe (blocked), got nil")
	}

	// All three violations at once are reported together (errors.Join).
	all := &Policy{RequireSecureBoot: false, SEDUnlock: SEDUnlockNone,
		Entries: []BootEntry{{Name: "t", Path: "EFI/TEST/TESTAPP.EFI", Validation: Firmware}}}
	err := all.CheckReleaseReady()
	if err == nil {
		t.Fatal("all-unsafe policy must fail")
	}
	for _, want := range []string{"require_secure_boot", "sed_unlock", "test-fixture"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error missing %q; got: %v", want, err)
		}
	}
}

// FuzzParse asserts Parse never panics on arbitrary input (it must fail closed via
// an error, never crash on attacker-controlled policy bytes).
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"entries":[{"name":"x","path":"a","validation":"firmware"}]}`))
	f.Add([]byte(`{"sed_unlock":"required","sed_pin":"correct horse","entries":[{"name":"x","path":"a","validation":"pba"}]}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
