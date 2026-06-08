# Shared fake-Opal spec & golden fixtures

Per [test-tooling-plan §3.2](../../../docs/test-tooling-plan.md). The native Go Opal
simulator (`internal/opal.MockTPer`, Go) and the EDK2 `MockOpalDxe` driver (C,
Phase 6) **cannot share code**, so they must share a **spec and golden fixtures** to
stay behaviourally consistent. These fixtures are the **source of truth**; both
implementations are validated against them.

## Canonical device

A locked Opal 2.0 SED with a shadow MBR:

| Property | Value |
|---|---|
| Opal SSC | v2 feature (0x0203) present |
| Session base ComID | `0x07FE` |
| Locking supported / enabled | yes / yes |
| Locked (global range) | **yes** |
| MBR enabled / done | enabled / **not** done |
| Admin1 credential | test-supplied (e.g. `correct horse`) |

## Fixtures

- **`discovery0-locked.bin`** — the Level 0 Discovery response for the canonical
  device (48-byte header + Locking feature `0x0002` + Opal SSC v2 feature `0x0203`).
  Byte-exact; `internal/opal.TestDiscoveryGoldenFixture` asserts it parses to the
  state above, so a format change is caught.

## Scripted unlock sequence (Admin1)

The byte-faithful exchange the simulator and driver must both implement:

1. **Level 0 Discovery** — IF-RECV(proto `0x01`, ComID `0x0001`) → `discovery0-locked.bin`.
2. **StartSession** — IF-SEND(proto `0x01`, base ComID) of
   `Call SMUID StartSession [ HSN, LockingSP, TRUE, Name0=PIN, Name3=Admin1 ]` →
   response `SyncSession [ HSN, TSN ]` with success status (wrong PIN → non-success
   status, no session).
3. **Set global range** — `Set Locking_GlobalRange { ReadLocked=0, WriteLocked=0 }`
   → success; device transitions to unlocked.
4. **Set MBRControl** — `Set MBRControl { Done=1 }` (only if MBR enabled and not
   already done) → success; shadow MBR no longer shadows.
5. **EndOfSession** — IF-SEND of the `0xFA` token → device replies `0xFA`.

Any failure at steps 2–4 (auth, status, transport) must **fail closed**: the device
stays locked and the PBA must not boot.

## UID / token reference

UIDs, method codes, table column numbers, and the stream token encoding are the
real TCG Opal SSC values (mirroring the Linux kernel `sed-opal` table), defined in
`internal/opal/{uid.go,token.go}`. Keeping the C driver's constants identical is what
makes the two layers interchangeable behind the `TCGTransport` interface.
