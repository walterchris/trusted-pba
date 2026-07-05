/*
 * tpmread — a minimal second-stage UEFI app that reads a TPM PCR via
 * EFI_TCG2_PROTOCOL.SubmitCommand and prints it over serial, used to characterize
 * the pba-override path's measured-boot (PCR 7) divergence (ADR-0012 task 5):
 * boot it via the override (out-of-db) vs firmware-db and compare the printed PCR 7.
 *
 * It reads PCR 7 (Secure Boot authority — what BitLocker seals to) and PCR 4
 * (boot image) with a raw TPM2_PCR_Read and prints "PCRn: <64 hex>\r\n".
 *
 * Self-contained / relocation-free (same constraints as testapp.c): no
 * InitializeLib, no globals/string literals, everything on the stack, hex computed
 * arithmetically. gnu-efi has no TCG2 header, so the protocol GUID and the
 * SubmitCommand slot (4th function pointer) are hand-rolled.
 */
#include <efi.h>
#include <efilib.h>

/* EFI_TCG2_PROTOCOL: SubmitCommand is the 4th member (byte offset 24). */
typedef struct {
	void *GetCapability;
	void *GetEventLog;
	void *HashLogExtendEvent;
	EFI_STATUS(EFIAPI *SubmitCommand)(void *This, UINT32 InSize, UINT8 *In,
	                                  UINT32 OutSize, UINT8 *Out);
} TCG2;

static void puts16(EFI_SYSTEM_TABLE *st, CHAR16 *s)
{
	uefi_call_wrapper(st->ConOut->OutputString, 2, st->ConOut, s);
}

/* read + print PCR `n` (SHA-256 bank) as "PCR<n>: <64 hex>\r\n". */
static void read_pcr(EFI_SYSTEM_TABLE *st, TCG2 *p, UINT8 n)
{
	/* TPM2_PCR_Read for one PCR in the SHA-256 bank (20-byte command). */
	UINT8 cmd[20];
	cmd[0] = 0x80; cmd[1] = 0x01;                       /* TPM_ST_NO_SESSIONS   */
	cmd[2] = 0; cmd[3] = 0; cmd[4] = 0; cmd[5] = 20;    /* commandSize = 20     */
	cmd[6] = 0; cmd[7] = 0; cmd[8] = 0x01; cmd[9] = 0x7e; /* TPM_CC_PCR_Read    */
	cmd[10] = 0; cmd[11] = 0; cmd[12] = 0; cmd[13] = 1; /* pcrSelectionCount=1  */
	cmd[14] = 0; cmd[15] = 0x0b;                        /* TPM_ALG_SHA256       */
	cmd[16] = 3;                                        /* sizeofSelect = 3     */
	cmd[17] = 0; cmd[18] = 0; cmd[19] = 0;              /* pcrSelect bitmap     */
	cmd[17 + (n / 8)] |= (UINT8)(1u << (n % 8));

	UINT8 out[128];
	EFI_STATUS s = uefi_call_wrapper(p->SubmitCommand, 5, p, (UINT32)20, cmd,
	                                 (UINT32)sizeof(out), out);

	CHAR16 line[80];
	int k = 0;
	line[k++] = L'P'; line[k++] = L'C'; line[k++] = L'R';
	line[k++] = (CHAR16)(L'0' + n);
	line[k++] = L':'; line[k++] = L' ';

	/* responseCode is out[6..9]; must be 0. For count=1/SHA-256 the 32-byte
	 * digest sits at offset 30 (hdr10 + updateCounter4 + selection10 + digestHdr6). */
	if (EFI_ERROR(s) || out[6] || out[7] || out[8] || out[9]) {
		line[k++] = L'E'; line[k++] = L'R'; line[k++] = L'R';
	} else {
		for (int i = 0; i < 32; i++) {
			UINT8 b = out[30 + i];
			UINT8 hi = (b >> 4) & 0xf, lo = b & 0xf;
			line[k++] = (CHAR16)(hi < 10 ? L'0' + hi : L'a' + (hi - 10));
			line[k++] = (CHAR16)(lo < 10 ? L'0' + lo : L'a' + (lo - 10));
		}
	}
	line[k++] = L'\r'; line[k++] = L'\n'; line[k] = 0;
	puts16(st, line);
}

EFI_STATUS EFIAPI
efi_main(EFI_HANDLE image_handle __attribute__((unused)), EFI_SYSTEM_TABLE *systab)
{
	/* EFI_TCG2_PROTOCOL_GUID 607f766c-7455-42be-930b-e4d76db2720f (stack-built). */
	EFI_GUID g;
	g.Data1 = 0x607f766c; g.Data2 = 0x7455; g.Data3 = 0x42be;
	g.Data4[0] = 0x93; g.Data4[1] = 0x0b; g.Data4[2] = 0xe4; g.Data4[3] = 0xd7;
	g.Data4[4] = 0x6d; g.Data4[5] = 0xb2; g.Data4[6] = 0x72; g.Data4[7] = 0x0f;

	void *tcg = 0;
	EFI_STATUS s = uefi_call_wrapper(systab->BootServices->LocateProtocol, 3,
	                                 &g, NULL, &tcg);
	if (EFI_ERROR(s) || !tcg) {
		CHAR16 m[24];
		int k = 0;
		m[k++] = L'T'; m[k++] = L'P'; m[k++] = L'M'; m[k++] = L'R'; m[k++] = L'D';
		m[k++] = L':'; m[k++] = L' '; m[k++] = L'n'; m[k++] = L'o'; m[k++] = L'-';
		m[k++] = L'T'; m[k++] = L'C'; m[k++] = L'G'; m[k++] = L'2';
		m[k++] = L'\r'; m[k++] = L'\n'; m[k] = 0;
		puts16(systab, m);
		return EFI_SUCCESS;
	}

	read_pcr(systab, (TCG2 *)tcg, 7);
	read_pcr(systab, (TCG2 *)tcg, 4);
	return EFI_SUCCESS;
}
