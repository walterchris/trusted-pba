// Package imageverify validates a second-stage UEFI image's Authenticode
// signature against an embedded Secure Boot trust store (db) and revocation list
// (dbx), reproducing how firmware authenticates an image. It lets the PBA act as
// a second-stage trust broker: verify a target (e.g. Windows Boot Manager) on its
// own, independent of — or in addition to — firmware Secure Boot.
//
// Like firmware Secure Boot, image acceptance does NOT depend on wall-clock time:
// the trust decision is membership of the signer's chain in db plus the absence of
// any chain certificate (or the image hash) from dbx. Signing-certificate validity
// periods are deliberately ignored — Microsoft's image-signing leaves are
// short-lived and routinely expired, yet the signed image must keep booting, and
// pre-boot firmware has no reliable clock. See ADR-0007; timestamp-countersignature
// validation is tracked as future research (#48).
//
// This package is pure Go (no UEFI calls), so it is host-testable and also builds
// under TamaGo. The trust material is injected by the caller.
package imageverify

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/foxboron/go-uefi/authenticode"
)

// Verifier holds a fixed trust store. Construct it from embedded Secure Boot
// materials (production) or test materials (tests).
type Verifier struct {
	// Roots is the db: CA certificates a valid signer must chain to.
	Roots []*x509.Certificate
	// DBXHashes is the dbx by image: revoked Authenticode SHA-256 digests, hex-encoded.
	DBXHashes map[string]struct{}
	// DBXCerts is the dbx by certificate: revoked signer/CA certificates.
	DBXCerts []*x509.Certificate
}

// Verification errors. Any non-nil error from Verify means "do not boot".
var (
	ErrParse       = errors.New("imageverify: cannot parse PE image")
	ErrNoSignature = errors.New("imageverify: image has no usable signature")
	ErrRevokedHash = errors.New("imageverify: image hash is revoked (dbx)")
	ErrRevokedCert = errors.New("imageverify: signer certificate is revoked (dbx)")
	ErrUntrusted   = errors.New("imageverify: signer does not chain to a trusted db certificate")
)

// Verify reproduces firmware image authentication and returns nil only if the
// image is trusted (see verify). Any error means fail closed.
func (v *Verifier) Verify(image []byte) error {
	_, err := v.verify(image)
	return err
}

// VerifyAnchor is Verify but, on success, also returns the db CA certificate the
// image's signer chained to — the authorizing authority. It backs the pba-override
// measured-boot record of who vouched for the image (ADR-0015).
func (v *Verifier) VerifyAnchor(image []byte) (*x509.Certificate, error) {
	return v.verify(image)
}

// verify is the shared implementation: it returns nil only if the image is trusted
// — its Authenticode hash is not revoked by dbx, its embedded signature binds that
// hash, the signer chains to a db CA, and no certificate in the signer's bundle or
// resolved chain (nor the db root) is revoked by dbx — and, on success, the db CA
// (chain root) it anchored to. Any error means fail closed.
func (v *Verifier) verify(image []byte) (anchor *x509.Certificate, err error) {
	// The go-uefi PE/Authenticode/PKCS#7 parsers run on attacker-controlled bytes
	// and can panic on malformed structures (e.g. an out-of-range PE size field
	// drives bytes.Buffer.Truncate out of range at checksum.go:179). A panic here
	// must never crash the PBA: recover and fail closed as an unparseable image.
	// See risk R-009 and FuzzVerify.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: panic parsing image: %v", ErrParse, r)
		}
	}()

	pe, err := authenticode.Parse(bytes.NewReader(image))
	if err != nil {
		return nil, errors.Join(ErrParse, err)
	}

	// dbx by image hash takes precedence over any trust decision.
	digest := pe.Hash(crypto.SHA256)
	if digest == nil {
		return nil, fmt.Errorf("%w: cannot hash image", ErrParse)
	}
	if _, revoked := v.DBXHashes[hex.EncodeToString(digest)]; revoked {
		return nil, ErrRevokedHash
	}

	sigs, err := pe.Signatures()
	if err != nil {
		return nil, errors.Join(ErrParse, err)
	}
	if len(sigs) == 0 {
		return nil, ErrNoSignature
	}

	// db roots, with validity periods neutralized (see ignoreValidity / package doc).
	roots := x509.NewCertPool()
	for _, c := range v.Roots {
		roots.AddCert(ignoreValidity(c))
	}

	// For each embedded signature, find the leaf signer (the cert whose key the
	// signature verifies against) and chain it to db, applying dbx by certificate.
	for _, sig := range sigs {
		ac, err := authenticode.ParseAuthenticode(sig.Certificate)
		if err != nil {
			continue // unparseable signature block; try the next embedded signature
		}
		certs := ac.Pkcs.Certs
		for _, leaf := range certs {
			if ok, err := pe.Verify(leaf); err != nil || !ok {
				continue // this cert did not sign the image; try the next candidate
			}
			// leaf signed the image (leaf ∈ certs, so this subsumes the leaf-only
			// check). Revocation is disqualifying anywhere in the signer's bundled
			// certs, not only on the chain x509.Verify ultimately returns: with a
			// cross-signed or otherwise alternate path to db, Verify can build a
			// winning chain that routes around a dbx-revoked intermediate the signer
			// stapled, so checking only the returned chain(s) would miss it. Fail
			// closed if any bundled cert is revoked (#91). (The per-chain loop below
			// additionally covers a revoked db root, which is not part of the
			// bundle.) A legitimate image does not bundle dbx-revoked material;
			// rejecting one is the safe pre-boot direction.
			if slices.ContainsFunc(certs, v.revoked) {
				return nil, ErrRevokedCert
			}
			intermediates := x509.NewCertPool()
			for _, c := range certs {
				if !c.Equal(leaf) {
					intermediates.AddCert(ignoreValidity(c))
				}
			}
			chains, err := ignoreValidity(leaf).Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				// Require code-signing EKU (ADR-0007 §3 step 3): a non-code-signing
				// cert (e.g. TLS serverAuth) that happens to chain to db must not
				// be allowed to boot an image. CurrentTime is left unset because
				// every certificate's validity has been neutralized.
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			})
			if err != nil {
				continue // this leaf does not chain to db; try the next candidate
			}
			for _, chain := range chains {
				for _, c := range chain {
					if v.revoked(c) {
						return nil, ErrRevokedCert
					}
				}
			}
			// Anchor = the db CA the winning chain terminated at. Return the
			// original v.Roots certificate (not the validity-neutralized copy in
			// the chain) so callers see the authentic DER for measurement.
			root := chains[0][len(chains[0])-1]
			for _, r := range v.Roots {
				if r.Equal(root) {
					return r, nil
				}
			}
			return root, nil
		}
	}
	return nil, ErrUntrusted
}

// ignoreValidity returns a copy of c whose validity period spans all time. UEFI
// Secure Boot does not reject an image because its signing certificate's validity
// window has lapsed (firmware has no reliable clock; Microsoft's image-signing
// leaves are short-lived and routinely expired), and we mirror that. The copy
// shares the original signed bytes (RawTBSCertificate/Signature/PublicKey), so the
// chain, EKU, and dbx checks are unaffected — only the time check is neutralized.
func ignoreValidity(c *x509.Certificate) *x509.Certificate {
	cp := *c
	cp.NotBefore = time.Time{}
	cp.NotAfter = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	return &cp
}

// revoked reports whether c appears in the dbx certificate list.
func (v *Verifier) revoked(c *x509.Certificate) bool {
	return slices.ContainsFunc(v.DBXCerts, c.Equal)
}
