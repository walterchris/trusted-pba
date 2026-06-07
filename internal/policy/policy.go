// Package policy is the PBA boot-trust policy: which second-stage image to boot
// and how it is validated. The policy is compiled into the binary (embedded JSON,
// see embed.go) and parsed fail-closed — any malformed or invalid policy yields an
// error and no usable policy, so the caller refuses to boot.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ValidationMode is how a boot entry's image is validated before it is started.
type ValidationMode string

const (
	// Firmware lets the firmware (Secure Boot) validate the image: the PBA just
	// calls LoadImage/StartImage — the Windows Boot Manager path.
	Firmware ValidationMode = "firmware"
	// PBA means the PBA validates the image itself (Authenticode vs embedded
	// db/dbx) before loading. Implemented in #41; until then it fails closed.
	PBA ValidationMode = "pba"
)

// BootEntry is one candidate boot target.
type BootEntry struct {
	Name       string         `json:"name"`
	Path       string         `json:"path"` // ESP-relative, e.g. "EFI/TEST/TESTAPP.EFI"
	Validation ValidationMode `json:"validation"`
}

// Policy is the compiled-in boot-trust policy.
type Policy struct {
	RequireSecureBoot bool        `json:"require_secure_boot"`
	Entries           []BootEntry `json:"entries"`
}

// Sentinel errors.
var (
	ErrNoEntries          = errors.New("policy has no boot entries")
	ErrSecureBootRequired = errors.New("policy requires Secure Boot enforcing")
)

// Parse decodes and validates a JSON policy. It fails closed: malformed input,
// unknown fields, or an invalid entry return an error and no policy. Parse never
// panics on arbitrary input (see the fuzz test).
func Parse(data []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if len(p.Entries) == 0 {
		return nil, ErrNoEntries
	}
	for i, e := range p.Entries {
		if e.Name == "" || e.Path == "" {
			return nil, fmt.Errorf("entry %d: name and path are required", i)
		}
		switch e.Validation {
		case Firmware, PBA:
		default:
			return nil, fmt.Errorf("entry %q: unknown validation mode %q", e.Name, e.Validation)
		}
	}
	return &p, nil
}

// Select returns the boot entry to use. For now this is the first (primary) entry;
// availability-ordered selection arrives with the chainloader wiring.
func (p *Policy) Select() (BootEntry, error) {
	if len(p.Entries) == 0 {
		return BootEntry{}, ErrNoEntries
	}
	return p.Entries[0], nil
}

// CheckSecureBoot fails closed when the policy requires Secure Boot enforcement but
// the firmware is not enforcing (CLAUDE.md: never treat Secure Boot disabled and
// enabled as equivalent).
func (p *Policy) CheckSecureBoot(enforcing bool) error {
	if p.RequireSecureBoot && !enforcing {
		return ErrSecureBootRequired
	}
	return nil
}
