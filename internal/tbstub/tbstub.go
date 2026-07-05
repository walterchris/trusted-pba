//go:build amd64

// Package tbstub is the trust-broker Security-override authorization primitive
// (ADR-0012/0013): a runtime-free asm stub installed as the firmware's
// EFI_SECURITY2_ARCH_PROTOCOL.FileAuthentication, plus the arm-state it reads.
//
// It is deliberately UEFI-free and builds on both TamaGo and the host, so the
// security-critical authorization decision (the stub's branches + one-shot disarm)
// is unit-testable on the host (see stub_test.go). The firmware plumbing — locating
// the protocol and swapping its function pointer — lives in cmd/pba, which drives
// this package.
//
// Not safe for concurrent use: the PBA is single-goroutine and pre-boot.
package tbstub

// Arm-state, read by the asm stub (stub_amd64.s) and written by Arm/Disarm. `armed`
// is written LAST as the release gate, so the stub never observes a half-armed
// record.
var (
	armed   uint64
	bufPtr  uint64 //nolint:unused // read by the asm stub (stub_amd64.s); write-only in Go
	bufSize uint64 //nolint:unused // read by the asm stub (stub_amd64.s); write-only in Go
	savedFn uint64 //nolint:unused // read by the asm stub (stub_amd64.s); write-only in Go
)

// securityStub is the FileAuthentication handler (asm, stub_amd64.s). Firmware calls
// it with the Microsoft x64 ABI; it is never called from Go — only its address is
// taken (StubAddr) and installed into the firmware protocol.
func securityStub() //nolint:unused // implemented in asm (stub_amd64.s); address taken via StubAddr

// StubAddr returns the raw entry address of securityStub, to write into the
// firmware Security2 protocol's FileAuthentication field.
func StubAddr() uint64

// Arm authorizes EXACTLY the buffer [ptr,size) for the next FileAuthentication call
// and records `original` — the firmware handler the stub tail-calls for anything
// else. Fields are set before `armed` (the release gate) so a concurrent-looking
// read can never see a partially-armed record.
func Arm(ptr uintptr, size uint64, original uint64) {
	bufPtr = uint64(ptr)
	bufSize = size
	savedFn = original
	armed = 1
}

// Disarm clears the armed flag. The stub also self-disarms on its one match, so a
// restore path calling Disarm is idempotent.
func Disarm() { armed = 0 }

// IsArmed reports whether the override is still armed (observability / tests).
func IsArmed() bool { return armed != 0 }
