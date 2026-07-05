//go:build tamago && amd64 && overridespike

#include "textflag.h"

// securityStub is the EFI_SECURITY2_ARCH_PROTOCOL.FileAuthentication handler the
// ADR-0012 spike installs (see override_spike.go). Firmware calls it with the
// Microsoft x64 ABI during LoadImage; it returns EFI_SUCCESS (0) UNCONDITIONALLY.
//
// SPIKE ONLY — a Secure Boot bypass, to prove firmware will call an installed asm
// stub and honor its verdict. NOSPLIT|NOFRAME: no Go prologue, no stack-split check
// — there is no valid `g` when firmware calls in, so the Go runtime must never be
// entered. Only RAX (a volatile register) is touched; all MS-ABI callee-saved
// registers are preserved.
TEXT ·securityStub(SB), NOSPLIT|NOFRAME, $0
	XORL	AX, AX		// EFI_SUCCESS
	RET

// securityStubAddr returns the raw entry address of securityStub, to install into
// the firmware Security2 protocol's FileAuthentication function-pointer field.
TEXT ·securityStubAddr(SB), NOSPLIT, $0-8
	LEAQ	·securityStub(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
