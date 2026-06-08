// Package imageverify validates a second-stage UEFI image's Authenticode
// signature against an embedded Secure Boot trust store (db) and revocation list
// (dbx), reproducing how firmware authenticates an image. It lets the PBA act as
// a second-stage trust broker: verify a target (e.g. Windows Boot Manager) on its
// own, independent of — or in addition to — firmware Secure Boot.
//
// This package is pure Go (no UEFI calls), so it is host-testable and also builds
// under TamaGo. The trust material and current time are injected by the caller.
package imageverify

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/foxboron/go-uefi/authenticode"
)

// Verifier holds a fixed trust store. Construct it from embedded Secure Boot
// materials (production) or test materials (tests).
type Verifier struct {
	// Roots is the db: CA certificates a valid signer must chain to.
	Roots *x509.CertPool
	// DBXHashes is the dbx by image: revoked Authenticode SHA-256 digests, hex-encoded.
	DBXHashes map[string]struct{}
	// DBXCerts is the dbx by certificate: revoked signer/CA certificates.
	DBXCerts []*x509.Certificate
	// Now is the time used for X.509 validity (the caller supplies an RTC reading
	// or a build-time floor; see ADR-0007).
	Now time.Time
}

// Verification errors. Any non-nil error from Verify means "do not boot".
var (
	ErrNoTime      = errors.New("imageverify: no verification time set")
	ErrParse       = errors.New("imageverify: cannot parse PE image")
	ErrNoSignature = errors.New("imageverify: image has no usable signature")
	ErrRevokedHash = errors.New("imageverify: image hash is revoked (dbx)")
	ErrRevokedCert = errors.New("imageverify: signer certificate is revoked (dbx)")
	ErrUntrusted   = errors.New("imageverify: signer does not chain to a trusted db certificate")
)

// Verify reproduces firmware image authentication and returns nil only if the
// image is trusted: its Authenticode hash is not revoked by dbx, its embedded
// signature binds that hash, the signer chains to a db CA, and no certificate in
// the chain is revoked by dbx. Any error means fail closed.
func (v *Verifier) Verify(image []byte) error {
	// Fail closed if the caller supplied no time: a zero CurrentTime makes the
	// stdlib silently substitute time.Now(), which pre-boot is unreliable and
	// would validate against an attacker-influenced clock. The caller must pass
	// an RTC reading or the build-time floor (ADR-0007).
	if v.Now.IsZero() {
		return ErrNoTime
	}

	pe, err := authenticode.Parse(bytes.NewReader(image))
	if err != nil {
		return errors.Join(ErrParse, err)
	}

	// dbx by image hash takes precedence over any trust decision.
	digest := pe.Hash(crypto.SHA256)
	if digest == nil {
		return fmt.Errorf("%w: cannot hash image", ErrParse)
	}
	if _, revoked := v.DBXHashes[hex.EncodeToString(digest)]; revoked {
		return ErrRevokedHash
	}

	sigs, err := pe.Signatures()
	if err != nil {
		return errors.Join(ErrParse, err)
	}
	if len(sigs) == 0 {
		return ErrNoSignature
	}

	// For each embedded signature, find the leaf signer (the cert whose key the
	// signature verifies against) and chain it to db, applying dbx by certificate.
	for _, sig := range sigs {
		ac, err := authenticode.ParseAuthenticode(sig.Certificate)
		if err != nil {
			continue
		}
		certs := ac.Pkcs.Certs
		for _, leaf := range certs {
			if ok, err := pe.Verify(leaf); err != nil || !ok {
				continue
			}
			// leaf signed the image. Reject immediately if the leaf is revoked.
			if v.revoked(leaf) {
				return ErrRevokedCert
			}
			intermediates := x509.NewCertPool()
			for _, c := range certs {
				if !c.Equal(leaf) {
					intermediates.AddCert(c)
				}
			}
			chains, err := leaf.Verify(x509.VerifyOptions{
				Roots:         v.Roots,
				Intermediates: intermediates,
				CurrentTime:   v.Now,
				// Require code-signing EKU (ADR-0007 §3 step 3): a non-code-signing
				// cert (e.g. TLS serverAuth) that happens to chain to db must not
				// be allowed to boot an image.
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			})
			if err != nil {
				continue // this leaf does not chain to db; try the next candidate
			}
			for _, chain := range chains {
				for _, c := range chain {
					if v.revoked(c) {
						return ErrRevokedCert
					}
				}
			}
			return nil
		}
	}
	return ErrUntrusted
}

// revoked reports whether c appears in the dbx certificate list.
func (v *Verifier) revoked(c *x509.Certificate) bool {
	for _, r := range v.DBXCerts {
		if c.Equal(r) {
			return true
		}
	}
	return false
}
