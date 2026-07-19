# MockOpalDxe — EDK2 mock Opal driver (test tooling)

Per [test-tooling-plan §3.3](../../docs/test-tooling-plan.md) (epic #22). A UEFI
DXE driver that installs `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` **and**
`EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` (#110) on a fresh handle and emulates the
canonical locked Opal 2.0 SED from the
[shared fake-Opal spec](../fixtures/opal/README.md), so both of the PBA's *real*
transport paths (Storage Security IF-SEND/IF-RECV, and NVMe Security
Send/Receive + Identify Controller) can be exercised in QEMU/OVMF without
hardware. The two protocol surfaces share one TPer state.

**Test tooling only.** Product code must never import or depend on it.

## Behaviour (kept consistent with `internal/opal.MockTPer`)

The C state machine mirrors the Go simulator byte-for-byte via the shared spec:
same UIDs (`internal/opal/uid.go`), token encoding (`token.go`), ComPacket
framing (`packet.go`), status codes, and the scripted Admin1 unlock sequence:

1. IF-RECV proto `0x01`, ComID `0x0001` → the golden
   `test/fixtures/opal/discovery0-locked.bin` bytes (embedded as the generated
   `Discovery0Locked.h`; the Locking-feature flags byte is patched from live
   state, which is the identity while the device is still locked).
2. `StartSession` on base ComID `0x07FE`: a correct Admin1 credential
   → `SyncSession [HSN, TSN=0x1000]` success; wrong credential → status `0x01`
   (`NOT_AUTHORIZED`, the real-drive wrong-PIN shape — the status the #112 auto
   iteration mode advances on), no session, device stays locked. Two credentials
   authenticate, modelling one drive reachable over two carriers: the raw PIN
   `correct horse` (no-hash provisioning, the Storage Security matrix) and its
   sedutil-pbkdf2 derivation at **75000** iterations over the scripted serial
   (hash-provisioned shape, the NVMe matrix — see `mAdmin1DerivedKey` in
   `MockOpalDxe.c`, drift-guarded by `TestMockDerivedKeySync`).
3. `Set Locking_GlobalRange { ReadLocked=0, WriteLocked=0 }` → unlocked.
4. `Set MBRControl { Done=1 }` → shadow MBR done.
5. `EndOfSession` (`0xFA`) → `0xFA` echo, session cleared.

Fail closed: any unexpected proto/ComID or garbled framing → `EFI_DEVICE_ERROR`;
any unparseable/unknown method or `Set` outside a session → `NOT_AUTHORIZED`
result; no state changes on any failure.

Intentional divergences from `MockTPer`: faults are selected by a UEFI variable
instead of `Inject()` (and cover different shapes — see below); state persists
for the lifetime of the boot (no re-arm); request token streams are capped at
`MAX_TOKENS` (64) tokens and staged responses at `RESP_MAX` (256) bytes —
anything larger fails closed (`NOT_AUTHORIZED` result), which real PBA traffic
never approaches.

Known gap: there is no `fail-garbled` fault shape yet (the equivalent of the Go
mock's `FaultMalformed`, which returns garbage bytes on IF-RECV), so the PBA's
tokenizer fail-closed path is QEMU-untested until one is added.

Note on `fail-after-unlock` (matches `MockTPer.resp` retention): after the
fault trips, only IF-SEND fails — the previously staged GlobalRange success
stream remains readable via IF-RECV. Negative tests must therefore assert via
`FORBID` on chainload/test-app markers, not on the absence of mock markers.

Regenerate the embedded discovery array after a fixture change with
`./gen-discovery-header.sh` (`build.sh` runs `--check` as a drift guard).

## NVMe pass-thru surface (#110)

The same handle carries `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` — the carrier of
the PBA's NVMe-passthru transport (`internal/transport/nvme_tamago.go`). Only
`PassThru` is functional (the only member the transport calls); it dispatches
admin command packets:

- **Identify Controller** (`0x06`, CNS=1) → zeroed 4096-byte identify data with
  the scripted 20-byte serial `TPBA-MOCK-0001      ` at bytes 4..23 — the
  sedutil-pbkdf2 PBKDF2 salt.
- **Security Send** (`0x81`) / **Security Receive** (`0x82`) → the shared TPer,
  SECP in Cdw10[31:24], SPSP (ComID) in Cdw10[23:8]. **ComID order differs by
  design:** this path takes the ComID in native TCG order (no swap), the
  Storage Security path un-swaps — mirroring the marshalling difference between
  the two real firmware carriers.

Because QEMU exposes no `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` unless a real
`-device nvme` is attached, this driver is the sole pass-thru instance in the
NVMe matrix — and omitting it makes "zero pass-thru handles → hard fail" a true
negative (see `test/qemu/nvme-opal-matrix.sh`).

## Building

```sh
./build.sh        # → MockOpalDxe.efi
```

Clones a pinned upstream edk2 (`EDK2_TAG` at the top of `build.sh`, currently
`edk2-stable202605`, verified against the pinned commit `EDK2_COMMIT` — tags
are mutable, commits are not) into `~/.cache/tpba-edk2/` (override:
`TPBA_EDK2_CACHE`), builds BaseTools once, and builds the driver from the
standalone `MockOpalPkg.dsc` in this directory via `PACKAGES_PATH` — the edk2
tree is never patched, so bumping the tag + commit pair is the whole upgrade.
Needs `git`, `make`, gcc/g++, `nasm`, `iasl`, libuuid headers, `python3`.

## Loading in QEMU/OVMF

BDS dispatches `Driver####` load options before any `Boot####` entry. Add the
entry to a VARS store with [`test/qemu/add-driver-entry.py`](../qemu/add-driver-entry.py)
and stage the driver via `run-qemu.sh`'s `DRIVER=` env (placed at
`\EFI\MOCK\MOCKOPALDXE.EFI` on the ESP):

```sh
./smoke.sh ../../bin/testapp.efi   # dispatch smoke (build testapp via `task testapp`)
```

**Competing instance note:** QEMU's IDE/SATA disks advertise IDENTIFY word 48
(Trusted Computing supported), so OVMF's AtaBus installs a *real*
`EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` instance on the QEMU disk handle, which
the PBA transport (first-instance only until Phase 8) may locate instead of
this driver. PBA-unlock runs therefore attach the ESP as virtio-blk
(`QEMU_DISK_IF=virtio` in `run-qemu.sh`), which carries no Storage Security —
see `test/qemu/mock-opal-matrix.sh`.

**Secure Boot note:** with enforcement active, BDS *silently* skips an
unsigned/unrevoked-unknown `Driver####` image — no error anywhere. That is why
the driver emits serial markers on COM1 (`0x3F8`, raw port I/O: the console is
not yet connected at `Driver####` dispatch). Absence of `MOCKOPAL: dispatched`
means the driver never ran. Under the enrolled Secure Boot VARS the driver
image must be signed with the test `db` key like the other test images.

## Serial markers (deterministic, for `expect-serial.py`)

| Marker | Meaning |
|---|---|
| `MOCKOPAL: dispatched` | driver entry reached |
| `MOCKOPAL: protocol installed` | SSC protocol installed on a handle |
| `MOCKOPAL: nvme passthru installed` | NVMe pass-thru protocol installed (same handle) |
| `MOCKOPAL: install failed` | protocol install failed (driver exits) |
| `MOCKOPAL: fault <mode> active` | fault mode armed from the variable |
| `MOCKOPAL: fault unknown failing closed as auth-fail` | unreadable/unknown variable value |
| `MOCKOPAL: startsession N` | Nth StartSession attempt this boot (capped at 9) — FORBID `startsession 2` asserts the auto loop stopped after one try |
| `MOCKOPAL: auth ok` / `MOCKOPAL: auth fail` | StartSession outcome |
| `MOCKOPAL: auth lockout` | `auth-lockout` fault hit (status `0x12`) |
| `MOCKOPAL: nvme identify` | Identify Controller served (serial/salt read) |
| `MOCKOPAL: unlocked` | global range read/write locks cleared |
| `MOCKOPAL: mbr-done set` | MBRControl Done set |
| `MOCKOPAL: mbr-refused fault` | `fail-mbrdone` fault hit |
| `MOCKOPAL: session end` | EndOfSession processed |

## Fault injection (no rebuild)

The driver reads the UEFI variable **`MockOpalFault`**, vendor GUID
**`a8d866f2-64a0-11f1-a8dc-56433c165986`**, once at dispatch. ASCII values
(trailing NUL tolerated):

| Value | Behaviour | Maps to PBA negative test |
|---|---|---|
| *(absent)* | normal scripted unlock | happy path |
| `auth-fail` | every `StartSession` → status `0x01` (`NOT_AUTHORIZED`, wrong-PIN shape) | wrong credential / auth failure |
| `auth-lockout` | every `StartSession` → status `0x12` (`AUTHORITY_LOCKED_OUT`) | try-limit exhausted — the #112 auto mode must stop immediately, never a second attempt |
| `fail-mbrdone` | `Set MBRControl` → `NOT_AUTHORIZED` method status | MBRDone refused (method-status error path) |
| `fail-after-unlock` | `Set GlobalRange` succeeds (device unlocks), every later IF-SEND → `EFI_DEVICE_ERROR` | partial unlock / transport drop (transport error path) |

Any other value fails closed: the driver arms `auth-fail` and says so on serial.

Set it offline in a VARS store with virt-firmware, e.g.:

```sh
virt-fw-vars --input vars.fd --output vars-fault.fd \
  --set-binary MockOpalFault a8d866f2-64a0-11f1-a8dc-56433c165986 <(printf auth-fail)
```

(or via the same Python API `add-driver-entry.py` uses).

## Files

- `MockOpalDxe.c` / `MockOpalDxe.inf` — the driver.
- `Discovery0Locked.h` — generated from the golden fixture (do not edit).
- `gen-discovery-header.sh` — regenerates/checks the header.
- `MockOpalPkg.dec` / `MockOpalPkg.dsc` — standalone EDK2 package/platform.
- `build.sh` — pinned-edk2 build → `MockOpalDxe.efi`.
- `smoke.sh` — Driver0000 dispatch smoke via the QEMU harness.
