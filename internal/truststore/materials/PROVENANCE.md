# Secure Boot trust materials — provenance

These are the embedded UEFI Secure Boot trust materials (`db` CA certificates and
the `dbx` revocation list) the PBA uses to validate second-stage images itself, as
mandated by [ADR-0007](../../../docs/architecture/adr/ADR-0007-policy-engine-and-verification.md).

All files are **byte-identical copies** of Microsoft's published artifacts (only the
filenames are normalized). Verify with `sha256sum` against the upstream repository.

## Source

- Upstream: <https://github.com/microsoft/secureboot_objects>
- Pinned commit: `e13abd50f3b5a7561052156a28c24fbf2bfbf6e3`
- These are public materials — no secrets, no private keys.

## `db` — trusted CA certificates (DER)

| Vendored file | Upstream path | SHA-256 | Subject CN | Set |
|---|---|---|---|---|
| `db/win-production-pca-2011.der` | `PreSignedObjects/DB/Certificates/MicWinProPCA2011_2011-10-19.der` | `e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961` | Microsoft Windows Production PCA 2011 | windows-only + full |
| `db/windows-uefi-ca-2023.der` | `PreSignedObjects/DB/Certificates/windows uefi ca 2023.der` | `076f1fea90ac29155ebf77c17682f75f1fdd1be196da302dc8461e350a9ae330` | Windows UEFI CA 2023 | windows-only + full |
| `db/ms-corp-uefi-ca-2011.der` | `PreSignedObjects/DB/Certificates/MicCorUEFCA2011_2011-06-27.der` | `48e99b991f57fc52f76149599bff0a58c47154229b9f8d603ac40d3500248507` | Microsoft Corporation UEFI CA 2011 | full only |
| `db/ms-uefi-ca-2023.der` | `PreSignedObjects/DB/Certificates/microsoft uefi ca 2023.der` | `f6124e34125bee3fe6d79a574eaa7b91c0e7bd9d929c1a321178efd611dad901` | Microsoft UEFI CA 2023 | full only |

The **windows-only** set (default) trusts only the two Windows CAs, so only Windows
Boot Manager validates via the `pba` path. The **full** set (build tag `trustfull`)
adds the third-party Microsoft UEFI CAs that sign shim/GRUB/Linux loaders.

## `dbx` — revocation list

| Vendored file | Upstream path | SHA-256 |
|---|---|---|
| `dbx/dbx-amd64.bin` | `PostSignedObjects/DBX/amd64/DBXUpdate.bin` | `74df077175dca7ff8bcd27ce8285656e38097803f803e2d124467273699e4b17` |

`dbx-amd64.bin` is an `EFI_VARIABLE_AUTHENTICATION_2`-wrapped update: a 16-byte
`EFI_TIME`, a `WIN_CERTIFICATE_UEFI_GUID` (whose `dwLength` field is at offset 16),
then the `EFI_SIGNATURE_LIST` payload at offset `16 + dwLength`. `truststore` strips
that authentication header and parses the trailing signature lists; we do not verify
the update's own PKCS#7 signature (we trust the pinned, hash-recorded artifact).

## Refresh process

Trust-anchor and revocation updates are **security-critical** and **ADR-gated**: bump
the pinned commit, replace the files, update the SHA-256s above, and record the change
in an ADR (per ADR-0007 "trust-anchor staleness"). Never edit these files by hand.
