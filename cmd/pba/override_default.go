//go:build tamago && amd64 && !overridespike

package main

import "io"

// maybeOverrideSpike is a no-op in normal builds. The ADR-0012 Security2-override
// spike (`-tags overridespike`) replaces it with the real stub installer
// (override_spike.go). It is called from run() just before chainload.
func maybeOverrideSpike(io.Writer) {}
