# Test report — Linux-boot matrix (first real-OS end-to-end)

- **Date:** 2026-07-21 (local runs; CI green run pending on the PR).
- **Branch:** `feat/linux-boot-matrix` (issue **#118** — fill in when opened).
- **Scope:** **test tooling only — no product code changed** (verified by the
  independent security review; diff vs `origin/main` touches only
  `test/fixtures/linuxinit/`, `test/qemu/build-linux-uki.sh`,
  `test/qemu/linux-boot-matrix.sh`, `Taskfile.yml` (`linux-boot-matrix` target),
  `.github/workflows/ci.yml` (`qemu-linux-matrix` job)).
- **Claim under test:** the product claim end-to-end — *unlock the SED, then
  boot an operating system*. The unchanged `-tags sedtest` PBA chainloads a
  **real Linux UKI** staged at the sedtest policy's existing target path
  (`EFI/TEST/TESTAPP.EFI`) after the MockOpalDxe mock-SED unlock.
- **Risks:** R-002 (real-OS NEG), R-007 (real-kernel positive), R-001 (POS-SB
  accept side). **No rating change.** **No ADR** (no product behavior change,
  baseline §23).
- **Docs:** `docs/test-tooling-plan.md` §3.8; threat model §9 (two new rows +
  the qualified harness-liveness row); risk assessment R-001/R-002/R-007 +
  2026-07-21 change-log row.
- **Reviews:** independent security review (initial **BLOCK** → fix → mutation
  proof; record: `evidence/security-review-records/2026-07-21-linux-boot-matrix.md`);
  go-reviewer **REQUEST CHANGES** on two lint nits (errcheck `f.Close`, gosec
  `nolint` justification) — both applied, `golangci-lint` 0 issues.

## Setup

- **PBA:** `trusted-pba-sedtest.efi` — the *unchanged* `-tags sedtest` build,
  same policy and unlock flow as `mock-opal-matrix.sh`; only the chainload
  target differs.
- **Mock SED:** EDK2 `MockOpalDxe.efi` (dispatched via `Driver0000`), fault
  injection via the harness's vars-based fault channel (`auth-fail`).
- **UKI:** built by `test/qemu/build-linux-uki.sh` with systemd `ukify` —
  distro kernel (local runs: the host's `vmlinuz`, `Linux version
  7.1.3-200.fc44`; CI: the runner's kernel via `TPBA_LINUX_KERNEL`) + a
  one-binary initramfs (`test/fixtures/linuxinit`: static Go PID-1,
  `CGO_ENABLED=0`, prints `TEST-LINUX: userspace ok` on serial, then powers
  off) + embedded cmdline `console=ttyS0,115200 panic=-1`. A **UKI, not a bare
  EFISTUB kernel**, because the PBA's chainloader passes no LoadOptions — the
  cmdline and initramfs must be embedded in the image.
- **Harness:** `run-qemu.sh` + `expect-serial.py` (REQUIRE/FORBID serial
  assertions), `QEMU_TIMEOUT=420` (TCG kernel decompression/boot is far beyond
  the 120s default), `QEMU_DISK_IF=virtio`; `harness-selftest.sh` re-proves the
  FORBID/grace semantics before any verdict is trusted.
- **Entry points:** `task linux-boot-matrix`; CI job `qemu-linux-matrix`
  (`.github/workflows/ci.yml`, uploads `linux-boot-serial.log`).

## Scenarios and results (all PASS locally, 2026-07-21)

| Scenario | Assertion shape | Result |
|---|---|---|
| **POS** — unlock → chainload UKI → Linux userspace | REQUIRE `MOCKOPAL: auth ok` → `MOCKOPAL: unlocked` → `MOCKOPAL: mbr-done set` → `TRUSTED-PBA: sed unlock ok` → `TEST-LINUX: userspace ok`; FORBID `TRUSTED-PBA: sed unlock failed`. **No** "chainload returned" REQUIRE — a kernel never returns to the firmware; the guest powers itself off. | PASS |
| **NEG** — auth-fail → the OS never boots | REQUIRE `MOCKOPAL: fault auth-fail active`, `MOCKOPAL: auth fail`, `TRUSTED-PBA: sed unlock failed`; FORBID `TRUSTED-PBA: sed unlock ok`, **`TRUSTED-PBA: starting`, `TRUSTED-PBA: ESP opened`** (the enforcing, grace-window-fitting detectors — see finding below), `TEST-LINUX: userspace ok` (defense-in-depth). | PASS (hardened form; first run + hardened re-run) |
| **POS-SB** — enforcing Secure Boot | Throwaway per-run test keys generated and enrolled (PK/KEK/db); driver + PBA + UKI all db-signed with `sbsign`; REQUIRE the POS chain plus `TRUSTED-PBA: secure-boot: enforcing`. Unsigned-UKI *rejection* is deliberately not duplicated here — covered non-vacuously by `secureboot-matrix`/`pba-matrix` (reviewer-confirmed). | PASS |

## Serial evidence highlights

- **POS / POS-SB:** kernel banner `Linux version 7.1.3-200.fc44` → EFI-stub
  handoff → `Run /init as init process` → `TEST-LINUX: userspace ok` →
  clean power-down (QEMU exits; harness judges markers seen).
- **NEG:** `MOCKOPAL: auth fail` → `TRUSTED-PBA: sed unlock failed` → terminal
  halt; **no kernel banner, no init, no userspace marker** — the kernel was
  held back entirely; no forbidden marker observed within the grace window.
- Full logs: local runs archived with the run outputs; CI uploads
  `linux-boot-serial.log` as the `linux-boot-serial-log` artifact.

## Security-review finding, fix, and mutation proof

- **Finding (independent security-review-agent, initial verdict BLOCK,
  empirically demonstrated):** the NEG's only fail-open detector was the
  userspace marker (`TEST-LINUX: userspace ok`). Under TCG that marker arrives
  **minutes** after the last REQUIRE — outside `expect-serial.py`'s **8s FORBID
  grace window** (`EXPECT_GRACE`) — so a fail-open PBA (one that logs
  `sed unlock failed` and chainloads anyway) would have **false-PASSed** the
  NEG. Reproduced via the harness's `EXPECT_STUB` seam.
- **Fix (applied per the review):** the NEG now FORBIDs the PBA's **early**
  chainload-side markers — `TRUSTED-PBA: starting` and
  `TRUSTED-PBA: ESP opened` — which a fail-open PBA emits within
  **milliseconds** of logging the unlock failure, comfortably inside the grace
  window. The userspace marker remains FORBIDden as defense-in-depth only. The
  `harness-selftest.sh` comment was corrected to state the grace-window
  precondition, and the threat-model §9 harness-liveness row is qualified: the
  self-test guarantees FORBID liveness **only for markers whose latency fits
  the grace window**.
- **Mutation proof (2026-07-21):** a deliberately fail-open PBA mutant (logged
  the unlock failure, continued to chainload; **never committed**) was built
  and run against the hardened NEG — caught with
  `FAIL: forbidden marker observed: TRUSTED-PBA: ESP opened`, exit 1. The
  product tree was reverted byte-identical afterward (`git checkout`, verified
  clean).

## Traceability

- **Requirement:** product claim (plan: unlock the SED, disable Shadow MBR,
  chainload the real OS); ER-1 (secure by default — real-OS NEG), ER-2
  (integrity — POS-SB signed-UKI accept side), ER-10 (regular security
  testing — the review finding + mutation proof are the process working).
- **Risks:** R-002 / R-007 / R-001 — detailed sections and the 2026-07-21
  change-log row in `docs/compliance/risk-assessment.md`.
- **Threat model:** §9 rows "Unlock then boot a real OS", "Unlock failure never
  boots a real OS", and the qualified harness-liveness row; §10 change-log
  entry 2026-07-21.
- **Tooling doc:** `docs/test-tooling-plan.md` §3.8 (+ roadmap §4, CI stages §5).
- **Review records:** `evidence/security-review-records/2026-07-21-linux-boot-matrix.md`
  (security); go-reviewer nits applied in-branch (lint clean).
- **ADR:** none required — test tooling only, no product behavior change
  (baseline §23); confirmed in both change logs.
