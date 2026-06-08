package truststore

import (
	"crypto/x509"
	"errors"
	"os"
	"testing"

	"github.com/walterchris/trusted-pba/internal/imageverify"
)

// TestRealMicrosoftSignedImage proves, against a genuine Microsoft-signed loader,
// two properties at once:
//
//   - the embedded third-party CA (full set) validates a real Microsoft-signed
//     image — i.e. we can boot something that is NOT in the windows-only default;
//   - the windows-only default trust set REJECTS that same image, so the
//     build-time trust-set boundary actually gates what boots.
//
// A distro shim (e.g. Ubuntu's shim-signed: /usr/lib/shim/shimx64.efi.signed*) is
// signed by the Microsoft Corporation/UEFI CA — the third-party CA in the full set
// — and is freely redistributable, unlike Windows Boot Manager. The binary is not
// committed; point TPBA_REAL_SHIM at one (CI installs shim-signed). The test skips
// when it is absent so normal runs stay deterministic.
//
// Acceptance is time-independent (see imageverify / ADR-0007): real Microsoft
// signing leaves are short-lived and routinely expired, so this would fail if we
// gated on signing-cert validity.
func TestRealMicrosoftSignedImage(t *testing.T) {
	path := os.Getenv("TPBA_REAL_SHIM")
	if path == "" {
		t.Skip("set TPBA_REAL_SHIM to a Microsoft-signed shim to run this test")
	}
	image, err := os.ReadFile(path) //nolint:gosec // test reads an operator/CI-provided shim path by design
	if err != nil {
		t.Fatalf("read shim %q: %v", path, err)
	}

	full := readCerts(t, "ms-corp-uefi-ca-2011.der", "ms-uefi-ca-2023.der",
		"win-production-pca-2011.der", "windows-uefi-ca-2023.der")
	windowsOnly := readCerts(t, "win-production-pca-2011.der", "windows-uefi-ca-2023.der")

	if err := (&imageverify.Verifier{Roots: full}).Verify(image); err != nil {
		t.Errorf("full trust set must accept a real Microsoft-signed shim, got %v", err)
	}
	if err := (&imageverify.Verifier{Roots: windowsOnly}).Verify(image); !errors.Is(err, imageverify.ErrUntrusted) {
		t.Errorf("windows-only must reject a third-party-CA-signed shim, got %v", err)
	}
}

func readCerts(t *testing.T, names ...string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for _, n := range names {
		der, err := os.ReadFile("materials/db/" + n) //nolint:gosec // fixed in-package material filenames
		if err != nil {
			t.Fatalf("read material %q: %v", n, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse material %q: %v", n, err)
		}
		out = append(out, cert)
	}
	return out
}
