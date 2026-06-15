// Package truststore builds the PBA's embedded Secure Boot trust store: the db CA
// certificates an image's signer must chain to, and the dbx revocation list
// (revoked image hashes and revoked certificates). The materials are byte-identical
// copies of Microsoft's published artifacts, pinned and recorded in
// materials/PROVENANCE.md (ADR-0007).
//
// The compiled-in db set is selected at build time: the default is windows-only;
// build with -tags trustfull for the full set (see embed_*.go). This package is
// pure Go (no UEFI calls), so it is host-testable and also builds under TamaGo.
package truststore

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/walterchris/trusted-pba/internal/imageverify"
)

// Store is the parsed embedded trust material.
type Store struct {
	// DB is the trusted CA certificates (db) a valid signer must chain to.
	DB []*x509.Certificate
	// DBXHashes is the set of revoked Authenticode SHA-256 digests, hex-encoded (dbx).
	DBXHashes map[string]struct{}
	// DBXCerts is the list of revoked certificates (dbx).
	DBXCerts []*x509.Certificate
}

// Load parses the compiled-in db certificates and dbx revocation list into a
// Store. It fails closed: any malformed material is an error, never a silently
// smaller trust store.
func Load() (*Store, error) {
	var db []*x509.Certificate
	for i, der := range dbCerts() {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("truststore: parse db cert %d: %w", i, err)
		}
		db = append(db, cert)
	}

	hashes, certs, err := parseDBX(dbxUpdateBytes())
	if err != nil {
		return nil, fmt.Errorf("truststore: parse dbx: %w", err)
	}
	// Defense in depth: the embedded dbx always carries revocations, so a parse
	// that yields none means the artifact or the parser is wrong. Fail closed
	// rather than boot with a silently empty revocation set.
	if len(hashes) == 0 && len(certs) == 0 {
		return nil, errors.New("truststore: dbx parsed to no revocations")
	}

	return &Store{DB: db, DBXHashes: hashes, DBXCerts: certs}, nil
}

// Verifier returns an imageverify.Verifier backed by this store. Image acceptance
// is time-independent (see imageverify / ADR-0007), so no clock is supplied.
func (s *Store) Verifier() *imageverify.Verifier {
	return &imageverify.Verifier{
		Roots:     s.DB,
		DBXHashes: s.DBXHashes,
		DBXCerts:  s.DBXCerts,
	}
}

// stripAuth2 removes the EFI_VARIABLE_AUTHENTICATION_2 header from a signed dbx
// update, returning the trailing EFI_SIGNATURE_LIST payload. Layout: a 16-byte
// EFI_TIME, then a WIN_CERTIFICATE_UEFI_GUID whose first field (dwLength, uint32)
// covers the whole certificate; the payload starts at 16 + dwLength.
func stripAuth2(b []byte) ([]byte, error) {
	const efiTimeLen = 16
	// dwLength spans the whole WIN_CERTIFICATE_UEFI_GUID: an 8-byte WIN_CERTIFICATE
	// header (dwLength + wRevision + wCertificateType) plus the 16-byte cert-type
	// GUID, so it can never be smaller than 24.
	const minWinCertLen = 24
	if len(b) < efiTimeLen+4 {
		return nil, errors.New("update too short for authentication header")
	}
	dwLength := binary.LittleEndian.Uint32(b[efiTimeLen : efiTimeLen+4])
	off := efiTimeLen + int(dwLength)
	if dwLength < minWinCertLen || off > len(b) {
		return nil, fmt.Errorf("invalid authentication header length %d", dwLength)
	}
	return b[off:], nil
}

// parseDBX strips the authentication header and parses the dbx signature lists
// into revoked image hashes (EFI_CERT_SHA256) and revoked certificates
// (EFI_CERT_X509). Unknown list types are ignored.
func parseDBX(update []byte) (map[string]struct{}, []*x509.Certificate, error) {
	esl, err := stripAuth2(update)
	if err != nil {
		return nil, nil, err
	}
	db, err := signature.ReadSignatureDatabase(bytes.NewReader(esl))
	if err != nil {
		return nil, nil, err
	}

	hashes := make(map[string]struct{})
	var certs []*x509.Certificate
	for _, sl := range db {
		switch sl.SignatureType {
		case signature.CERT_SHA256_GUID:
			for _, sig := range sl.Signatures {
				if len(sig.Data) != crypto.SHA256.Size() {
					return nil, nil, fmt.Errorf("dbx: bad SHA256 entry length %d", len(sig.Data))
				}
				hashes[hex.EncodeToString(sig.Data)] = struct{}{}
			}
		case signature.CERT_X509_GUID:
			for _, sig := range sl.Signatures {
				cert, err := x509.ParseCertificate(sig.Data)
				if err != nil {
					return nil, nil, fmt.Errorf("dbx: parse X509 entry: %w", err)
				}
				certs = append(certs, cert)
			}
		case signature.CERT_EXTERNAL_MANAGEMENT_GUID:
			// Legitimately carries no revocation entries (UEFI 2.10 §32.4.1): the
			// list is managed by an external agent. Nothing to enforce; skip.
		default:
			// Any other ESL type carries revocation entries this parser cannot
			// enforce (e.g. SHA-384/512 hashes). Dropping them would silently
			// shrink the revocation set, so fail closed rather than under-revoke.
			return nil, nil, fmt.Errorf("dbx: unsupported ESL signature type %v", sl.SignatureType)
		}
	}
	return hashes, certs, nil
}
