/*
 * testapp — a minimal second-stage UEFI application used as a Phase 1 chainload
 * fixture for Trusted PBA. It prints a unique success marker and returns
 * EFI_SUCCESS, which hands control back to the PBA's StartImage() caller (it does
 * NOT shut down or call ExitBootServices).
 *
 * Built with gnu-efi (see Taskfile `testapp`), but deliberately self-contained:
 *  - It does NOT call InitializeLib and uses no global/library state, and
 *  - it builds the marker on the stack with immediate characters (no string
 *    literal),
 * so it needs ZERO relocations. gnu-efi's self-relocation on this binutils leaves
 * global pointers (string literals, library globals) unfixed, which printed
 * garbage; using only the passed system table sidesteps relocation entirely.
 *
 * gnu-efi is used rather than a second TamaGo image because TamaGo's uefi/x64
 * runtime re-initializes the CPU and heap on entry, which faults when run on top
 * of the already-running PBA.
 */
#include <efi.h>
#include <efilib.h>

EFI_STATUS EFIAPI
efi_main(EFI_HANDLE image_handle __attribute__((unused)), EFI_SYSTEM_TABLE *systab)
{
	/* "TEST-APP: ok\r\n" built from immediates on the stack — no relocations. */
	CHAR16 msg[16];
	msg[0] = L'T'; msg[1] = L'E'; msg[2] = L'S'; msg[3] = L'T'; msg[4] = L'-';
	msg[5] = L'A'; msg[6] = L'P'; msg[7] = L'P'; msg[8] = L':'; msg[9] = L' ';
	msg[10] = L'o'; msg[11] = L'k'; msg[12] = L'\r'; msg[13] = L'\n'; msg[14] = 0;

	/* ConOut is routed to serial under headless OVMF, so this reaches the QEMU
	 * -serial backend. uefi_call_wrapper keeps the firmware call correct under
	 * gnu-efi's traditional (non-MS-ABI) model used by the distro libs. */
	uefi_call_wrapper(systab->ConOut->OutputString, 2, systab->ConOut, msg);

	/* Return to the caller (the PBA's StartImage), not ResetSystem. */
	return EFI_SUCCESS;
}
