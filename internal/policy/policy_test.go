package policy

import (
	"errors"
	"testing"
)

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(`{"require_secure_boot":true,"entries":[{"name":"win","path":"EFI/Microsoft/Boot/bootmgfw.efi","validation":"firmware"}]}`))
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
		"no entries":         `{"entries":[]}`,
		"missing path":       `{"entries":[{"name":"x","validation":"firmware"}]}`,
		"missing name":       `{"entries":[{"path":"a","validation":"pba"}]}`,
		"unknown validation": `{"entries":[{"name":"x","path":"a","validation":"magic"}]}`,
		"unknown field":      `{"entries":[{"name":"x","path":"a","validation":"pba","extra":1}]}`,
		"wrong type":         `{"require_secure_boot":"yes","entries":[]}`,
	}
	for name, in := range bad {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
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

// FuzzParse asserts Parse never panics on arbitrary input (it must fail closed via
// an error, never crash on attacker-controlled policy bytes).
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"entries":[{"name":"x","path":"a","validation":"firmware"}]}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
