//go:build tamago && amd64 && !trustbroker

package main

import "fmt"

// verifyAndLoadOverride fails closed in normal builds: the SHIM-style Secure Boot
// override (ADR-0012 — validation mode "pba-override") is compiled only with
// -tags trustbroker, so it stays out of default and release builds until its
// acceptance ADR lands. A policy that uses pba-override validation therefore
// refuses to boot on a normal build rather than silently downgrading.
func verifyAndLoadOverride(string) error {
	return fmt.Errorf("%s: pba-override not built (needs -tags trustbroker)", chainloadFail)
}
