// Command release-policy-check fails (non-zero exit) unless the given boot-policy
// JSON is safe to embed in a RELEASE build (policy.CheckReleaseReady): Secure Boot
// required, the SED unlock not skipped, and no test-fixture boot target. The
// release workflow runs it as a gate (Taskfile check-release-policy); it is a host
// tool and never part of the trusted-pba.efi binary.
//
// Usage: release-policy-check [policy.json]   (default: internal/policy/policy.json)
package main

import (
	"fmt"
	"os"

	"github.com/walterchris/trusted-pba/internal/policy"
)

func main() {
	path := "internal/policy/policy.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	data, err := os.ReadFile(path) //nolint:gosec // release-gate CLI reads an operator/CI-provided policy path by design
	if err != nil {
		fmt.Fprintf(os.Stderr, "release-policy-check: %v\n", err)
		os.Exit(2)
	}
	p, err := policy.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "release-policy-check: %s: invalid policy: %v\n", path, err)
		os.Exit(2)
	}
	if err := p.CheckReleaseReady(); err != nil {
		fmt.Fprintf(os.Stderr, "RELEASE BLOCKED: %s is not release-ready:\n%v\n", path, err)
		os.Exit(1)
	}
	fmt.Printf("release-policy-check: %s is release-ready\n", path)
}
