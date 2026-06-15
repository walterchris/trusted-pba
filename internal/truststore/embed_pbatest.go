//go:build pbatest

package truststore

import _ "embed"

// TrustSet names the compiled-in db set for diagnostics.
const TrustSet = "pbatest"

// testDBCert is a single self-signed code-signing certificate generated at test
// time by test/qemu/pba-matrix.sh and written here just before the `-tags pbatest`
// build. It is the only trusted db CA in this build, so the QEMU pba matrix can
// sign a fixture with the matching key and exercise the real verify-then-load path
// against firmware-independent trust material. NEVER ship this build; the file is
// git-ignored and absent from normal checkouts.
//
//go:embed testdata/test-db.der
var testDBCert []byte

func dbCerts() [][]byte {
	return [][]byte{testDBCert}
}

// testDBX is a crafted signed dbx update generated at test time by
// test/qemu/pba-setup.sh (via make-test-dbx.py): a single EFI_CERT_X509 revocation
// of the leaf cert used to sign bin/pbatest/testapp-revoked.efi. It lets the QEMU
// pba matrix exercise the real dbx-by-certificate revocation path against
// firmware-independent trust material. NEVER ship this build; the file is
// git-ignored and absent from normal checkouts.
//
//go:embed testdata/test-dbx.bin
var testDBX []byte

// dbxUpdateBytes returns the crafted test dbx (see testDBX). The non-pbatest builds
// (embed_windowsonly.go / embed_full.go) return the real Microsoft dbx instead.
func dbxUpdateBytes() []byte {
	return testDBX
}
