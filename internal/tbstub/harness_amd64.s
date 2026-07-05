//go:build amd64

#include "textflag.h"

// callStub(this, devPath, fileBuffer, fileSize, bootPolicy uintptr) uintptr
// Calls securityStub with the Microsoft x64 ABI (RCX/RDX/R8/R9 + a stack 5th arg,
// over 32 bytes of shadow space) exactly as firmware does, and returns RAX.
TEXT ·callStub(SB), NOSPLIT, $48-48
	MOVQ	this+0(FP), CX
	MOVQ	devPath+8(FP), DX
	MOVQ	fileBuffer+16(FP), R8
	MOVQ	fileSize+24(FP), R9
	MOVQ	bootPolicy+32(FP), AX
	MOVQ	AX, 32(SP)		// 5th arg, above the 32-byte shadow space
	LEAQ	·securityStub(SB), AX
	CALL	AX
	MOVQ	AX, ret+40(FP)
	RET

// fakeOriginal — MS-ABI stand-in for the original firmware FileAuthentication;
// returns a recognizable sentinel (0xDEAD) so tests can spot the chain path.
TEXT ·fakeOriginal(SB), NOSPLIT|NOFRAME, $0
	MOVQ	$0xDEAD, AX
	RET

// fakeOriginalAddr returns &fakeOriginal.
TEXT ·fakeOriginalAddr(SB), NOSPLIT, $0-8
	LEAQ	·fakeOriginal(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
