package opal

import (
	"errors"
	"os"
	"testing"
)

func TestDiscoveryRoundTrip(t *testing.T) {
	want := &Discovery{
		OpalSSC: true, BaseComID: 0x07fe,
		LockingSupported: true, LockingEnabled: true, Locked: true,
		MBREnabled: true, MBRDone: false,
	}
	got, err := parseDiscovery(buildDiscovery(want))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *got != *want {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseDiscoveryFailsClosed(t *testing.T) {
	good := buildDiscovery(&Discovery{OpalSSC: true, BaseComID: 0x07fe, LockingSupported: true})
	cases := map[string][]byte{
		"short header": good[:10],
		"no opal ssc":  buildDiscovery(&Discovery{LockingSupported: true})[:discoveryHdrLen], // header only, no features
		"bad length":   append([]byte{0xff, 0xff, 0xff, 0xff}, good[4:]...),
		"empty":        {},
	}
	for name, in := range cases {
		if _, err := parseDiscovery(in); !errors.Is(err, ErrDiscovery) {
			t.Errorf("%s: want ErrDiscovery, got %v", name, err)
		}
	}
}

// TestDiscoveryGoldenFixture locks the byte format: the committed fixture is the
// shared source of truth the EDK2 MockOpalDxe (Phase 6) must reproduce.
func TestDiscoveryGoldenFixture(t *testing.T) {
	raw, err := os.ReadFile("../../test/fixtures/opal/discovery0-locked.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	d, err := parseDiscovery(raw)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	want := &Discovery{
		OpalSSC: true, BaseComID: 0x07fe,
		LockingSupported: true, LockingEnabled: true, Locked: true, MBREnabled: true,
	}
	if *d != *want {
		t.Fatalf("fixture changed:\n got %+v\nwant %+v", d, want)
	}
}
