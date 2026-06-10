module github.com/walterchris/trusted-pba

go 1.26.4

// UEFI x86_64 board support (CPU/serial/EFI-System-Table bring-up) lives in
// go-boot's uefi/x64 package; tamago is the bare-metal Go runtime. Keep the
// tamago library minor in lockstep with the tamago-go toolchain (go1.26.4).
// Dependencies are resolved/pinned by `task deps` (go get + mod tidy under
// GOOS=tamago); the require block below is populated on first resolution.

require (
	github.com/foxboron/go-uefi v0.0.0-20251010190908-d29549a44f29
	// Pinned fork of usbarmory/go-boot v1.6.2 adding
	// EFI_STORAGE_SECURITY_COMMAND_PROTOCOL for the Opal transport (ADR-0008)
	// and LoadImageBuffer for verified-buffer chainloading (#46).
	github.com/walterchris/go-boot v1.6.2-tpba.2
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/u-root/u-root v0.15.0 // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/usbarmory/tamago v1.26.4 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)
