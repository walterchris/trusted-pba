//go:build tamago && amd64 && trustbroker

#include "textflag.h"

// securityStub is installed as EFI_SECURITY2_ARCH_PROTOCOL.FileAuthentication and
// called by firmware (Microsoft x64 ABI) on LoadImage:
//
//	EFI_STATUS FileAuthentication(This, DevicePath, FileBuffer, FileSize, BootPolicy)
//	  RCX=This  RDX=DevicePath  R8=FileBuffer  R9=FileSize  [RSP+0x28]=BootPolicy
//
// It authorizes EXACTLY the one armed buffer (pointer + size identity — the PBA
// hands that same SourceBuffer to LoadImageBuffer) and one-shot disarms. Any
// mismatch, or not armed, TAIL-CALLS the saved original firmware handler with the
// arguments intact — so normal Secure Boot validation still applies to anything
// else. Only RAX (a volatile register) is used before the tail-call, so RCX/RDX/
// R8/R9 pass through unchanged; no MS-ABI callee-saved register is touched.
//
// NOSPLIT|NOFRAME: no Go prologue / stack-split check — there is no valid `g` when
// firmware calls in, so the Go runtime is never entered.
TEXT ·securityStub(SB), NOSPLIT|NOFRAME, $0
	MOVQ	·sbArmed(SB), AX
	TESTQ	AX, AX
	JZ	chain			// not armed -> firmware validates
	MOVQ	·sbBufPtr(SB), AX
	CMPQ	AX, R8			// FileBuffer == armed pointer?
	JNE	chain
	MOVQ	·sbBufSize(SB), AX
	CMPQ	AX, R9			// FileSize == armed size?
	JNE	chain
	// exact match: one-shot disarm, return EFI_SUCCESS (0)
	MOVQ	$0, ·sbArmed(SB)
	XORL	AX, AX
	RET
chain:
	MOVQ	·sbSavedFn(SB), AX
	JMP	AX			// tail-call the original handler, args intact

// securityStubAddr returns the raw entry address of securityStub, to install into
// the firmware Security2 protocol's FileAuthentication function-pointer field.
TEXT ·securityStubAddr(SB), NOSPLIT, $0-8
	LEAQ	·securityStub(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
