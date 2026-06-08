//go:build !trustfull && !pbatest

package truststore

import _ "embed"

// TrustSet names the compiled-in db set for diagnostics.
const TrustSet = "windows-only"

//go:embed materials/db/win-production-pca-2011.der
var winProductionPCA2011 []byte

//go:embed materials/db/windows-uefi-ca-2023.der
var windowsUEFICA2023 []byte

// dbCerts returns the DER-encoded db CA certificates to trust. The default
// (windows-only) set trusts just the two Windows CAs, so only Windows Boot
// Manager validates via the pba path. Build with -tags trustfull to also trust
// the third-party Microsoft UEFI CAs (shim/GRUB/Linux). See ADR-0007.
func dbCerts() [][]byte {
	return [][]byte{winProductionPCA2011, windowsUEFICA2023}
}
