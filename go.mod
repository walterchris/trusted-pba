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
	// and LoadImageBuffer for verified-buffer chainloading (#46). tpba.3 fixes
	// the SSC service dispatch (double dereference) and callFn's stack
	// alignment for odd stack-argument counts — both caught by the mock-Opal
	// QEMU integration matrix (#22).
	github.com/walterchris/go-boot v1.6.2-tpba.5
)

require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/arl/statsviz v0.8.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/gliderlabs/ssh v0.3.8 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hako/durafmt v0.0.0-20210608085754-5c1018a4e16b // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/u-root/u-root v0.15.0 // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/usbarmory/armory-boot v0.0.0-20260202115234-edf170b30f66 // indirect
	github.com/usbarmory/go-net v0.0.0-20251003201608-93d9ffe808de // indirect
	github.com/usbarmory/tamago v1.26.4 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/crypto/x509roots/fallback v0.0.0-20260209214922-2f26647a795e // indirect
	golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/term v0.40.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	gvisor.dev/gvisor v0.0.0-20250911055229-61a46406f068 // indirect
)

replace github.com/walterchris/go-boot => /home/nabla/workspace/9elements/projects/go-boot
