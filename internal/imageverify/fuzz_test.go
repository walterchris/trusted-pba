package imageverify

import (
	"crypto/x509"
	"os"
	"testing"
)

// FuzzVerify exercises Verify with arbitrary image bytes — the bytes an attacker
// can place on the ESP for the PBA to authenticate. Verify parses attacker-
// controlled PE/Authenticode/PKCS#7 structures via foxboron/go-uefi; per the
// compliance baseline §12 (and risk R-009) that parsing must never panic — it must
// fail closed. The Verifier carries a real root plus a revoked hash and a revoked
// cert (root.cert is in both Roots and DBXCerts) so every branch is reachable: the
// signed seed chains to the root and is then rejected by dbx-by-cert, exercising
// the full parse → signature → chain-walk → revocation path.
func FuzzVerify(f *testing.F) {
	root := newCA(f, "fuzz root")
	leaf, leafKey := root.leaf(f, "fuzz leaf")

	signed := signFixture(f, leafKey, leaf, root.cert)
	unsigned, err := os.ReadFile("testdata/sample-pe.bin")
	if err != nil {
		f.Fatalf("read sample PE: %v", err)
	}

	v := &Verifier{
		Roots: []*x509.Certificate{root.cert},
		// A dummy dbx-by-hash entry keeps that branch present; the exact value is
		// irrelevant to a no-panic fuzz.
		DBXHashes: map[string]struct{}{
			"0000000000000000000000000000000000000000000000000000000000000000": {},
		},
		DBXCerts: []*x509.Certificate{root.cert},
	}

	f.Add(signed)
	f.Add(unsigned)
	f.Add([]byte{})
	f.Add([]byte("MZ"))                                   // truncated DOS header
	f.Add([]byte{'M', 'Z', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // junk past the magic

	f.Fuzz(func(_ *testing.T, image []byte) {
		// Must fail closed, never panic, on any input. The error/nil result is not
		// asserted — only that the parsers survive arbitrary bytes.
		_ = v.Verify(image)
	})
}
