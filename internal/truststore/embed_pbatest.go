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
