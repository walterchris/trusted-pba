// Package transport provides concrete opal.Transport carriers. The UEFI carrier
// drives a drive's EFI_STORAGE_SECURITY_COMMAND_PROTOCOL (IF-SEND/IF-RECV); a
// !tamago host stub keeps the package buildable and testable off-target. The Opal
// protocol logic lives in internal/opal and depends only on the interface.
package transport

import "github.com/walterchris/trusted-pba/internal/opal"

// UEFI and NVMe must satisfy the Opal transport interface in every build.
var (
	_ opal.Transport = (*UEFI)(nil)
	_ opal.Transport = (*NVMe)(nil)
)
