package secureboot

import "testing"

func TestEnforcing(t *testing.T) {
	cases := []struct {
		name string
		s    State
		want bool
	}{
		{"off", State{}, false},
		{"setup-mode only", State{SetupMode: true}, false},
		{"secureboot on but setup mode", State{SecureBoot: true, SetupMode: true}, false},
		{"enforcing", State{SecureBoot: true}, true},
	}
	for _, c := range cases {
		if got := c.s.Enforcing(); got != c.want {
			t.Errorf("%s: Enforcing() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestString(t *testing.T) {
	cases := map[string]State{
		"enforcing":       {SecureBoot: true},
		"on (setup mode)": {SecureBoot: true, SetupMode: true},
		"off":             {},
	}
	for want, s := range cases {
		if got := s.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}
