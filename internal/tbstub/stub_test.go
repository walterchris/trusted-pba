//go:build amd64

package tbstub

import (
	"testing"
	"unsafe"
)

// TestStubAuthorizesOnlyArmedBuffer exercises every branch of the security-critical
// authorization stub by calling it through the Microsoft x64 ABI (as firmware does)
// via callStub, with fakeOriginal as the "original" handler. It is the mutation
// guard for the override: inverting a branch or dropping the one-shot disarm flips
// one of these cases (ADR-0013 pre-merge requirement F2).
//
// EFI_SUCCESS is 0; fakeOriginal returns 0xDEAD, so a 0xDEAD result means the stub
// took the chain (tail-call original) path and did NOT authorize.
func TestStubAuthorizesOnlyArmedBuffer(t *testing.T) {
	const chain = uintptr(0xDEAD)
	buf := make([]byte, 4096)
	ptr := uintptr(unsafe.Pointer(&buf[0])) //nolint:gosec // test needs raw pointer identity to exercise the stub
	size := uint64(len(buf))
	orig := fakeOriginalAddr()

	// 1. armed + exact (ptr,size) match -> EFI_SUCCESS and one-shot disarm.
	Arm(ptr, size, orig)
	if got := callStub(0, 0, ptr, uintptr(size), 0); got != 0 {
		t.Fatalf("armed+match: got 0x%x, want 0 (EFI_SUCCESS)", got)
	}
	if IsArmed() {
		t.Error("armed+match: stub must one-shot disarm")
	}

	// 2. immediately re-called (now disarmed) -> must chain, not re-authorize.
	if got := callStub(0, 0, ptr, uintptr(size), 0); got != chain {
		t.Errorf("second call after disarm: got 0x%x, want chain 0x%x", got, chain)
	}

	// 3. armed but WRONG SIZE -> chain, and stays armed (no match consumed).
	Arm(ptr, size, orig)
	if got := callStub(0, 0, ptr, uintptr(size+1), 0); got != chain {
		t.Errorf("wrong size: got 0x%x, want chain", got)
	}
	if !IsArmed() {
		t.Error("wrong size: must stay armed (nothing authorized)")
	}

	// 4. armed but DIFFERENT POINTER (same size) -> chain.
	buf2 := make([]byte, len(buf))
	ptr2 := uintptr(unsafe.Pointer(&buf2[0])) //nolint:gosec // test needs raw pointer identity to exercise the stub
	Arm(ptr, size, orig)
	if got := callStub(0, 0, ptr2, uintptr(size), 0); got != chain {
		t.Errorf("wrong pointer: got 0x%x, want chain", got)
	}

	// 5. NOT armed -> chain.
	Disarm()
	if got := callStub(0, 0, ptr, uintptr(size), 0); got != chain {
		t.Errorf("not armed: got 0x%x, want chain", got)
	}
}
