package imageverify

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/pkcs7"
)

type ca struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newCA(t testing.TB, cn string) ca {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca{cert, key}
}

// leaf issues a code-signing leaf cert + key signed by the CA.
func (c ca) leaf(t testing.TB, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	return c.leafEKU(t, cn, x509.ExtKeyUsageCodeSigning)
}

// leafEKU issues a leaf cert + key signed by the CA with the given extended key usage.
func (c ca) leafEKU(t testing.TB, cn string, eku x509.ExtKeyUsage) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	return c.leafValidity(t, cn, eku, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
}

// leafValidity issues a leaf cert + key with an explicit validity window so tests
// can exercise expired signers.
func (c ca) leafValidity(t testing.TB, cn string, eku x509.ExtKeyUsage, notBefore, notAfter time.Time) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// intermediate issues a subordinate CA cert + key signed by the CA.
func (c ca) intermediate(t testing.TB, cn string) ca {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca{cert, key}
}

// signFixture signs the PE fixture with leafKey/leafCert, embedding extra certs
// (e.g. the issuing CA) so a verifier can build the chain.
func signFixture(t testing.TB, leafKey *rsa.PrivateKey, leafCert *x509.Certificate, extra ...*x509.Certificate) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/sample-pe.bin")
	if err != nil {
		t.Fatal(err)
	}
	pe, err := authenticode.Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse fixture PE: %v", err)
	}
	if _, err := pe.Sign(leafKey, leafCert, pkcs7.WithAdditionalCerts(extra)); err != nil {
		t.Fatalf("sign fixture: %v", err)
	}
	return pe.Bytes()
}

func imageHash(t *testing.T, image []byte) string {
	t.Helper()
	pe, err := authenticode.Parse(bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pe.Hash(crypto.SHA256))
}

func TestVerifyAccepts(t *testing.T) {
	root := newCA(t, "Test db CA")
	leafCert, leafKey := root.leaf(t, "Test Signer")
	signed := signFixture(t, leafKey, leafCert, root.cert)

	v := &Verifier{Roots: []*x509.Certificate{root.cert}}
	if err := v.Verify(signed); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

// TestVerifyAnchorReturnsRoot asserts VerifyAnchor returns the db CA the signer
// chained to (the authority measured into PCR 7 by the pba-override path, ADR-0015).
func TestVerifyAnchorReturnsRoot(t *testing.T) {
	root := newCA(t, "Test db CA")
	leafCert, leafKey := root.leaf(t, "Test Signer")
	signed := signFixture(t, leafKey, leafCert, root.cert)

	v := &Verifier{Roots: []*x509.Certificate{root.cert}}
	anchor, err := v.VerifyAnchor(signed)
	if err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	if anchor == nil || !anchor.Equal(root.cert) {
		t.Fatalf("anchor = %v, want the db root %q", anchor, root.cert.Subject)
	}
	// The returned cert must be the authentic v.Roots entry (real DER for
	// measurement), not a validity-neutralized copy.
	if anchor != root.cert {
		t.Errorf("anchor is not the original v.Roots cert pointer")
	}
}

// TestVerifyAcceptsExpiredSigner asserts the firmware-matching policy: a signer
// whose validity window has lapsed must still verify, because UEFI Secure Boot does
// not gate on signing-cert expiry (real Microsoft image-signing leaves are routinely
// expired). See ADR-0007.
func TestVerifyAcceptsExpiredSigner(t *testing.T) {
	root := newCA(t, "Test db CA")
	expired := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	leafCert, leafKey := root.leafValidity(t, "Expired Signer", x509.ExtKeyUsageCodeSigning,
		time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), expired)
	signed := signFixture(t, leafKey, leafCert, root.cert)

	v := &Verifier{Roots: []*x509.Certificate{root.cert}}
	if err := v.Verify(signed); err != nil {
		t.Fatalf("expired signer must still be accepted (firmware semantics), got %v", err)
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	root := newCA(t, "Test db CA")
	leafCert, leafKey := root.leaf(t, "Test Signer")
	signed := signFixture(t, leafKey, leafCert, root.cert)
	other := newCA(t, "Untrusted CA")

	t.Run("tampered image", func(t *testing.T) {
		bad := bytes.Clone(signed)
		bad[len(bad)/3] ^= 0xff // mutate hashed content
		v := &Verifier{Roots: []*x509.Certificate{root.cert}}
		if err := v.Verify(bad); err == nil {
			t.Fatal("tampered image must be rejected")
		}
	})

	t.Run("untrusted root", func(t *testing.T) {
		v := &Verifier{Roots: []*x509.Certificate{other.cert}}
		if err := v.Verify(signed); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("want ErrUntrusted, got %v", err)
		}
	})

	t.Run("unsigned image", func(t *testing.T) {
		raw, _ := os.ReadFile("testdata/sample-pe.bin")
		v := &Verifier{Roots: []*x509.Certificate{root.cert}}
		if err := v.Verify(raw); !errors.Is(err, ErrNoSignature) {
			t.Fatalf("want ErrNoSignature, got %v", err)
		}
	})

	t.Run("revoked by image hash (dbx)", func(t *testing.T) {
		v := &Verifier{
			Roots:     []*x509.Certificate{root.cert},
			DBXHashes: map[string]struct{}{imageHash(t, signed): {}},
		}
		if err := v.Verify(signed); !errors.Is(err, ErrRevokedHash) {
			t.Fatalf("want ErrRevokedHash, got %v", err)
		}
	})

	t.Run("revoked by signer cert (dbx)", func(t *testing.T) {
		v := &Verifier{Roots: []*x509.Certificate{root.cert}, DBXCerts: []*x509.Certificate{root.cert}}
		if err := v.Verify(signed); !errors.Is(err, ErrRevokedCert) {
			t.Fatalf("want ErrRevokedCert, got %v", err)
		}
	})

	t.Run("non-code-signing EKU", func(t *testing.T) {
		// A leaf that chains to db but carries serverAuth (not codeSigning) must
		// not be allowed to boot, even though the chain is otherwise valid.
		tlsCert, tlsKey := root.leafEKU(t, "TLS Server", x509.ExtKeyUsageServerAuth)
		tlsSigned := signFixture(t, tlsKey, tlsCert, root.cert)
		v := &Verifier{Roots: []*x509.Certificate{root.cert}}
		if err := v.Verify(tlsSigned); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("want ErrUntrusted, got %v", err)
		}
	})

	t.Run("revoked intermediate via chain walk", func(t *testing.T) {
		// Root -> intermediate -> leaf, where dbx revokes the intermediate. The
		// chain validates, but the chain walk must catch the revoked intermediate.
		inter := root.intermediate(t, "Test Intermediate CA")
		leafCert2, leafKey2 := inter.leaf(t, "Sub Signer")
		subSigned := signFixture(t, leafKey2, leafCert2, inter.cert, root.cert)
		v := &Verifier{
			Roots:    []*x509.Certificate{root.cert},
			DBXCerts: []*x509.Certificate{inter.cert},
		}
		if err := v.Verify(subSigned); !errors.Is(err, ErrRevokedCert) {
			t.Fatalf("want ErrRevokedCert, got %v", err)
		}
	})

	t.Run("revoked bundled cert off the winning chain (#91)", func(t *testing.T) {
		// The leaf chains DIRECTLY to the db root, so x509.Verify's winning chain
		// is [leaf, root] and never includes the extra intermediate the signer also
		// stapled into the PKCS#7 bundle. That extra cert is dbx-revoked. Checking
		// only the returned chain(s) would miss it and boot the image (the #91 gap);
		// checking the full bundle rejects it. Mutation guard: reverting the
		// full-bundle loop in verify.go makes this the only failing subtest.
		revoked := root.intermediate(t, "Revoked Bundled CA")
		bundledSigned := signFixture(t, leafKey, leafCert, root.cert, revoked.cert)
		v := &Verifier{
			Roots:    []*x509.Certificate{root.cert},
			DBXCerts: []*x509.Certificate{revoked.cert},
		}
		if err := v.Verify(bundledSigned); !errors.Is(err, ErrRevokedCert) {
			t.Fatalf("want ErrRevokedCert for a revoked bundled cert off the winning chain, got %v", err)
		}
	})
}
