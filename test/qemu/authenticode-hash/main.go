// Command authenticode-hash prints the hex-encoded Authenticode SHA-256 digest
// of a PE/COFF image — the same digest UEFI firmware computes when matching an
// image against dbx by hash, and the same one internal/imageverify uses for its
// DBXHashes check.
//
// It exists so the Secure Boot test matrix can revoke a db-trusted PBA image by
// its Authenticode hash (virt-fw-vars --add-dbx-hash) and prove the firmware
// rejects it, without pulling in a separate Authenticode tool (pesign et al.):
// it reuses go-uefi, the library the product itself verifies images with, so the
// test hash and the enforced hash come from one source of truth.
//
//	authenticode-hash <image.efi>
package main

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/foxboron/go-uefi/authenticode"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: authenticode-hash <image.efi>")
		os.Exit(2)
	}

	image, err := os.ReadFile(os.Args[1]) //nolint:gosec // CLI helper reads an operator/CI-provided image path by design
	if err != nil {
		fmt.Fprintf(os.Stderr, "authenticode-hash: %v\n", err)
		os.Exit(1)
	}

	pe, err := authenticode.Parse(bytes.NewReader(image))
	if err != nil {
		fmt.Fprintf(os.Stderr, "authenticode-hash: parse PE: %v\n", err)
		os.Exit(1)
	}

	digest := pe.Hash(crypto.SHA256)
	if digest == nil {
		fmt.Fprintln(os.Stderr, "authenticode-hash: cannot hash image")
		os.Exit(1)
	}

	fmt.Println(hex.EncodeToString(digest))
}
