# Trusted PBA — Test Tooling Plan (Virtual Testing)

> Scope: this document covers **the tools we build only to test the product
> virtually** — simulators, mock drivers, firmware/key material, the QEMU runner,
> and test fixtures. The product itself (`trusted-pba.efi`) is specified in
> [`trusted-pba-plan.md`](trusted-pba-plan.md). Keep the two tracks separate: test
> tooling must never be required for the product to function, and product code
> must never depend on test-tooling code.

## 1. Decision: EDK2 mock driver now, QEMU device model later

These two routes test **different layers**, so the choice is about sequencing, not
exclusivity:

- An **EDK2 mock DXE driver** tests *our* code. It installs
  `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` on a handle and answers
  `SendData`/`ReceiveData` like a fake Opal device. The PBA locates and drives that
  protocol inside real OVMF exactly as it would on hardware. Self-contained, no
  QEMU fork, deterministic, CI-friendly. EDK2's `NvmExpressDxe` / `OpalPasswordDxe`
  serve as reference for how the protocol is produced/consumed.
- A **QEMU device model** tests the layer *below* our code — the firmware's own SSC
  implementation, the ATA/NVMe security commands, and real **Shadow-MBR block
  visibility** (locked disk hides the real ESP; MBRDone reveals it). It is the only
  way to virtually exercise in-session MBRDone (open questions R-008 / plan §14).

**Decision (chosen):**
1. **Now** — build the EDK2 `MockOpalDxe` driver as the recommended virtual
   integration test, on top of the native Go Opal simulator.
2. **Later** — keep a QEMU virtual SED device model as a planned phase, to validate
   Shadow-MBR block visibility and in-session MBRDone virtually. Only build it once
   the PBA architecture is proven; real-hardware bring-up (plan §Phase 8) may answer
   the same questions with more authority and reduce its priority.

> The QEMU route requires patching/forking QEMU (its NVMe/AHCI models do not
> implement TCG Opal security send/receive today) **and** depends on OVMF driver
> support to surface the protocol. Treat committing to the QEMU model as an
> architecture decision warranting an ADR
> (`docs/architecture/adr/`) at the time we start it.

## 2. Layered virtual test strategy

Four layers, increasing fidelity and cost. The default development loop uses
layers 1–2; layer 3 is the planned-later investment; layer 4 is hardware (covered
by the product plan, not here).

| Layer | Tool | What it validates | When |
|------|------|-------------------|------|
| 1 | Native Go Opal simulator (`MockTransport`) | Opal command/session logic, no UEFI | `go test ./...`, every change |
| 2 | EDK2 `MockOpalDxe` driver in OVMF | PBA's real UEFI protocol path — **both product carriers** (locate + drive the SSC protocol, and locate + drive the NVMe pass-thru protocol incl. Identify-serial salt, #110), full virtual unlock + chainload | PR CI (QEMU) — **primary virtual integration test** |
| 3 | QEMU virtual SED device model | firmware SSC mapping, Shadow-MBR block visibility, in-session MBRDone | **Later phase**, after architecture proven |
| 4 | Real SED hardware | real firmware/drive behavior, compatibility matrix | Nightly/release (see product plan §Phase 8) |

## 3. Tool inventory / deliverables

### 3.1 Native Go Opal simulator (`internal/transport/mock.go`, `test/...`)
Fake Opal device behind the `TCGTransport` interface. Simulates Discovery0,
supported ComIDs, StartSession, Authenticate, Locking SP state, global-range
lock/unlock, `MBRControl.Enable`/`Done`, plus failure cases: wrong password,
unsupported feature, invalid ComID, malformed response, timeout. No block
encryption needed. Runs without QEMU.

### 3.2 Shared fake-Opal spec & golden fixtures (`test/fixtures/opal/`)
The native Go simulator (Go) and the EDK2 `MockOpalDxe` (C) cannot share code, so
they **must share a spec and golden fixtures**: canonical Discovery0 blobs,
scripted request→response sequences, and error scenarios. This keeps layers 1 and 2
behaviourally consistent. Treat the fixtures as the source of truth; both
implementations are validated against them.

### 3.3 EDK2 MockOpalDxe driver (`test/edk2-mock-opal/`)
`MockOpalDxe.inf` + `MockOpalDxe.c`. A UEFI DXE driver that installs
`EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` on a handle and implements deterministic
`SendData`/`ReceiveData` from the shared spec (§3.2). Loaded before the PBA in
QEMU/OVMF (from the ESP or built into the OVMF image). Must be able to simulate
both success and failure so the PBA can be shown to **fail closed** on Opal
failure.

**Extended (2026-07-19, #110): NVMe pass-thru surface.** The driver additionally
produces `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` on the **same handle**, so the one
mock now covers **both product transport carriers**: Identify Controller returns
a scripted 20-byte serial (`"TPBA-MOCK-0001      "`, space-padded — the
sedutil-pbkdf2 PBKDF2 salt)
and Security Send/Receive (`0x81`/`0x82`) dispatch into the **shared** scripted
TPer with the ComID in **native TCG order** (no swap — the product NVMe
carrier's contract), while the Storage Security surface keeps its swap
(mirroring the real firmware marshalling difference). A second accepted Admin1
credential — the PBKDF2 derivation of the shared-spec passphrase at 75000
iterations — models a hash-provisioned drive; it is drift-guarded against the
KAT-verified `SedutilPBKDF2` primitive by `TestMockDerivedKeySync`
(`internal/credential`). New `auth-lockout` fault (StartSession →
`AUTHORITY_LOCKED_OUT 0x12`) and `MOCKOPAL: startsession N` attempt markers
support try-limit assertions. **Decision:** extend the existing driver rather
than build a separate `MockNvmePassThru` driver or start the QEMU device model
(§3.7 stays **deferred**) — one shared TPer keeps the two carriers behaviourally
consistent via the shared spec (§3.2), and because QEMU exposes no pass-thru
protocol without a real `-device nvme`, omitting the driver yields a true
zero-instance "no pass-thru handle → hard fail" negative
(`test/qemu/nvme-opal-matrix.sh`, CI job `qemu-nvme-matrix`).

### 3.4 OVMF + Secure Boot test key material (`test/qemu/ovmf/`, `test/qemu/keys/`)
Test `PK`/`KEK`/`db`/`dbx` and OVMF variable stores (`OVMF_CODE.fd`,
per-scenario `OVMF_VARS.fd`) for Secure-Boot-on and Secure-Boot-off variants.
**Test keys only — never production keys; never commit private keys** (compliance
baseline §13). Signing via `sbsigntool` or equivalent.

### 3.5 QEMU runner + serial-expect harness (`test/qemu/`)
`run-qemu.sh` (x86_64, KVM if available, OVMF code/vars, serial console logging,
FAT ESP image, optional second disk) and `expect-serial.py` (asserts on start
markers and chainload success/failure markers; drives the Secure Boot matrix and
mock-Opal integration runs). Plus an ESP image builder that stages the PBA, the
mock driver, fixtures, and target EFI apps.

### 3.6 EFI test fixtures (`test/fixtures/`)
`unsigned.efi`, `signed-good.efi`, `signed-bad.efi`, `revoked.efi`,
`windows-placeholder.efi`, `grub-placeholder.efi` — minimal EFI apps that print a
known marker, used to exercise chainload accept/reject, firmware-validated vs
PBA-validated paths, and revocation.

### 3.7 QEMU virtual SED device model — **LATER**
Extend a QEMU storage device (NVMe / AHCI-SATA / SCSI) to model a locked SED:
locked state exposes the Shadow-MBR image and hides the real disk; security
send/receive implements a fake Opal session; MBRDone disables the Shadow MBR and
exposes the real ESP. Requires QEMU C internals expertise and likely a maintained
fork/out-of-tree patch. **Not in MVP.** Gate behind an ADR.

## 4. Test-tooling roadmap (aligned to product phases)

| Tooling deliverable | Aligns with product phase |
|---------------------|---------------------------|
| QEMU runner + serial harness + ESP builder (§3.5) | Phase 0 (skeleton / smoke test) |
| EFI test fixtures (§3.6) | Phase 1 (boot-manager MVP) |
| OVMF + Secure Boot key material (§3.4) | Phase 2 (Secure Boot matrix) |
| Native Go Opal simulator + shared fixtures (§3.1–3.2) | Phase 4 (Opal native simulator) |
| EDK2 MockOpalDxe driver (§3.3) | Phase 6 (UEFI mock Opal driver) |
| QEMU virtual SED device model (§3.7) | **Later** — after architecture proven |

## 5. Virtual CI stages (no hardware)

Runs on every PR, deterministic, hardware-free:

```
lint -> unit tests (Go Opal simulator) -> fuzz smoke -> SAST -> dependency scan
-> SBOM -> QEMU UEFI smoke -> QEMU Secure Boot matrix -> QEMU mock-Opal integration
-> chainload tests -> negative policy/security tests
```

Hardware CI (real SED, Shadow MBR, Windows/Linux chainload, recovery, PSID reset)
runs nightly/manually and is isolated from PR CI — see product plan §Phase 8/9 and
compliance baseline §17–18.

## 6. Tooling principles

- Test tooling is never required for the product to run; product code never imports
  test-tooling code.
- Prefer deterministic virtual tests over hardware-dependent ones.
- Every hardware-only behavior must have a documented mock equivalent here.
- Mocks must be able to produce failure as well as success, so the PBA can be shown
  to fail closed.
- Layers 1 and 2 stay consistent via the shared spec/fixtures (§3.2).

## 7. Tooling-specific open questions

- ~~Does OVMF reliably load an external `MockOpalDxe.efi` from the ESP before the PBA,
  or must it be built into the OVMF image?~~ **Answered — see decision below.**
- What is the minimum the EDK2 mock must implement for the PBA to consider a device
  a valid Opal target (Discovery0 feature set, ComID handling)?
- For the later QEMU model: which device class (NVMe vs AHCI) gives the best OVMF
  SSC-protocol support with the least patching?
- Can the QEMU model faithfully reproduce in-session MBRDone, or is that ultimately
  a hardware-only validation?

### Decision (spike, 2026-06-10): load `MockOpalDxe.efi` from the ESP via `Driver0000`/`DriverOrder`

Do **not** build it into OVMF and do **not** introduce an EFI shell. Verified
empirically on stock Fedora `edk2-ovmf` (20250812) through the existing harness: a
`Driver0000` load option with a short-form file-path device path
(`\EFI\...\MOCKOPALDXE.EFI`) is dispatched by BDS before any `Boot####` option,
both in Setup Mode and under enforcing Secure Boot when the driver is db-signed.
`virt-fw-vars`' Python library (`virt.firmware`) writes the entry offline into the
per-run VARS copy in ~20 lines, fitting the existing `OVMF_VARS` override and
`sbsign` flow of `secureboot-matrix.sh`. Building the mock into OVMF would force us
to maintain a forked firmware build and would bypass Secure Boot image verification
for the driver; a `startup.nsh`/shell approach would replace the harness's direct
`BOOTX64.EFI` boot path and put a signed scriptable shell into the trust set.

**Fail-closed caveat:** under enforcing Secure Boot an unsigned/wrong-key driver is
*silently skipped* and boot continues, so Phase 6 tests must REQUIRE a
driver-emitted serial marker (and the PBA's protocol-located marker) so a rejected
mock can never produce a false pass.

**Build prerequisites for Phase 6** (beyond what the harness already uses): a
pinned edk2 source checkout (release tag, submodule or CI clone) plus BaseTools —
either distro `edk2-tools` (prebuilt `GenFw`/`GenFv`) or `make -C BaseTools` in the
checkout. Toolchain deps (gcc/g++, make, nasm, iasl, libuuid-devel, python3) are
standard.
