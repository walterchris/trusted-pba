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

// verifyTime is within every test certificate's validity window.
var verifyTime = time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)

type ca struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newCA(t *testing.T, cn string) ca {
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
func (c ca) leaf(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
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

func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// signFixture signs the PE fixture with leafKey/leafCert, embedding extra certs
// (e.g. the issuing CA) so a verifier can build the chain.
func signFixture(t *testing.T, leafKey *rsa.PrivateKey, leafCert *x509.Certificate, extra ...*x509.Certificate) []byte {
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

	v := &Verifier{Roots: pool(root.cert), Now: verifyTime}
	if err := v.Verify(signed); err != nil {
		t.Fatalf("expected accept, got %v", err)
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
		v := &Verifier{Roots: pool(root.cert), Now: verifyTime}
		if err := v.Verify(bad); err == nil {
			t.Fatal("tampered image must be rejected")
		}
	})

	t.Run("untrusted root", func(t *testing.T) {
		v := &Verifier{Roots: pool(other.cert), Now: verifyTime}
		if err := v.Verify(signed); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("want ErrUntrusted, got %v", err)
		}
	})

	t.Run("unsigned image", func(t *testing.T) {
		raw, _ := os.ReadFile("testdata/sample-pe.bin")
		v := &Verifier{Roots: pool(root.cert), Now: verifyTime}
		if err := v.Verify(raw); !errors.Is(err, ErrNoSignature) {
			t.Fatalf("want ErrNoSignature, got %v", err)
		}
	})

	t.Run("revoked by image hash (dbx)", func(t *testing.T) {
		v := &Verifier{
			Roots:     pool(root.cert),
			DBXHashes: map[string]struct{}{imageHash(t, signed): {}},
			Now:       verifyTime,
		}
		if err := v.Verify(signed); !errors.Is(err, ErrRevokedHash) {
			t.Fatalf("want ErrRevokedHash, got %v", err)
		}
	})

	t.Run("revoked by signer cert (dbx)", func(t *testing.T) {
		v := &Verifier{Roots: pool(root.cert), DBXCerts: []*x509.Certificate{root.cert}, Now: verifyTime}
		if err := v.Verify(signed); !errors.Is(err, ErrRevokedCert) {
			t.Fatalf("want ErrRevokedCert, got %v", err)
		}
	})
}
