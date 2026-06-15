#!/usr/bin/env python3
"""Craft a minimal signed dbx update that revokes one X.509 leaf certificate.

The output mirrors a real EFI_VARIABLE_AUTHENTICATION_2 dbx update closely enough
for internal/truststore's stripAuth2 + go-uefi signature parser to accept it, but
it carries exactly one EFI_CERT_X509 revocation: the DER cert handed in. That cert
is the leaf used to sign bin/pbatest/testapp-revoked.efi, so the PBA's
dbx-by-certificate check (imageverify.Verifier.revoked, c.Equal on raw DER) rejects
that otherwise-validly-signed, db-chaining image.

Layout written (all multi-byte fields little-endian):

  [16-byte EFI_TIME — zeros; stripAuth2 skips it, value is irrelevant]
  WIN_CERTIFICATE_UEFI_GUID:
    dwLength  uint32 = 24      (8-byte WIN_CERTIFICATE header + 16-byte cert GUID;
                                stripAuth2 starts the ESL at 16 + dwLength)
    wRevision uint16 = 0x0200
    wCertType uint16 = 0x0EF1  (WIN_CERT_TYPE_EFI_GUID)
    16-byte cert-type GUID      (EFI_CERT_TYPE_PKCS7 — unused by stripAuth2)
  ESL — one EFI_SIGNATURE_LIST:
    SignatureType       = EFI_CERT_X509_GUID (mixed-endian GUID bytes)
    SignatureListSize   uint32 = 28 + SignatureSize
    SignatureHeaderSize uint32 = 0
    SignatureSize       uint32 = 16 + len(certDER)
    one EFI_SIGNATURE_DATA: 16-byte owner GUID (arbitrary) + certDER

    make-test-dbx.py <leaf-cert-DER> <output-dbx>
"""
import struct
import sys

# EFI_CERT_X509_GUID a5c059a1-94e4-4aa7-87b5-ab155c2bf072 in the on-disk
# mixed-endian GUID layout (Data1/Data2/Data3 little-endian, Data4 big-endian) —
# the exact bytes go-uefi/efi/util.EFIGUID writes for signature.CERT_X509_GUID.
# A round-trip through go-uefi's parser (truststore.parseDBX) verifies this.
CERT_X509_GUID = bytes(
    [0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A,
     0x87, 0xB5, 0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72]
)

# Arbitrary cert-type GUID for the WIN_CERTIFICATE_UEFI_GUID header (EFI_CERT_TYPE_
# PKCS7 4aafd29d-...); stripAuth2 only uses dwLength, so the value does not matter.
WIN_CERT_TYPE_PKCS7_GUID = bytes(
    [0x9D, 0xD2, 0xAF, 0x4A, 0xDF, 0x68, 0xEE, 0x49,
     0x8A, 0xA9, 0x34, 0x7D, 0x37, 0x56, 0x65, 0xA7]
)

# Arbitrary owner GUID for the revocation entry (UEFI lets this be any value).
OWNER_GUID = bytes(range(16))


def main() -> int:
    if len(sys.argv) != 3:
        sys.exit("usage: make-test-dbx.py <leaf-cert-DER> <output-dbx>")
    cert = open(sys.argv[1], "rb").read()

    # EFI_TIME: 16 zero bytes (skipped by stripAuth2).
    efi_time = b"\x00" * 16

    # WIN_CERTIFICATE_UEFI_GUID header. dwLength covers the 8-byte WIN_CERTIFICATE
    # header plus the 16-byte cert-type GUID = 24; no PKCS7 payload follows because
    # stripAuth2 jumps straight past it to the ESL.
    win_cert = struct.pack("<IHH", 24, 0x0200, 0x0EF1) + WIN_CERT_TYPE_PKCS7_GUID

    # EFI_SIGNATURE_DATA = owner GUID + cert DER.
    sig_data = OWNER_GUID + cert
    signature_size = len(sig_data)  # 16 + len(cert)

    # EFI_SIGNATURE_LIST header: type, total list size, header size (0), per-sig size.
    list_size = 16 + 4 + 4 + 4 + signature_size
    esl = CERT_X509_GUID + struct.pack("<III", list_size, 0, signature_size) + sig_data

    open(sys.argv[2], "wb").write(efi_time + win_cert + esl)
    print(f"make-test-dbx: revoked 1 leaf cert -> {sys.argv[2]} ({len(cert)} B DER)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
