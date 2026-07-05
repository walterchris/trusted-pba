//go:build amd64

package tbstub

// Test support (harness_amd64.s). These let the host test drive the asm stub the way
// firmware does — through the Microsoft x64 ABI — without a UEFI. They are referenced
// only from stub_test.go, so the linker dead-strips them from the PBA binary.

// callStub invokes securityStub with the MS x64 ABI and returns its status (RAX).
func callStub(this, devPath, fileBuffer, fileSize, bootPolicy uintptr) uintptr

// fakeOriginal is a stand-in "original firmware handler" that returns a sentinel so
// a test can detect the stub's tail-call (chain) path. Never called from Go.
func fakeOriginal()

// fakeOriginalAddr returns the address of fakeOriginal, for Arm's `original` arg.
func fakeOriginalAddr() uint64
