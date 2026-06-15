//go:build trustfull && !pbatest

package truststore

import _ "embed"

// TrustSet names the compiled-in db set for diagnostics.
const TrustSet = "full"

//go:embed materials/db/win-production-pca-2011.der
var winProductionPCA2011 []byte

//go:embed materials/db/windows-uefi-ca-2023.der
var windowsUEFICA2023 []byte

//go:embed materials/db/ms-corp-uefi-ca-2011.der
var msCorpUEFICA2011 []byte

//go:embed materials/db/ms-uefi-ca-2023.der
var msUEFICA2023 []byte

//go:embed materials/dbx/dbx-amd64.bin
var dbxUpdate []byte

// dbxUpdateBytes returns the signed dbx update to parse for revocations: the real,
// byte-identical Microsoft amd64 dbx (see materials/PROVENANCE.md). The pbatest
// build (embed_pbatest.go) substitutes a crafted test dbx via the same function.
func dbxUpdateBytes() []byte {
	return dbxUpdate
}

// dbCerts returns the DER-encoded db CA certificates to trust. The full set
// (build tag trustfull) trusts the Windows CAs plus the third-party Microsoft
// UEFI CAs that sign shim/GRUB/Linux loaders. See ADR-0007.
func dbCerts() [][]byte {
	return [][]byte{winProductionPCA2011, windowsUEFICA2023, msCorpUEFICA2011, msUEFICA2023}
}
