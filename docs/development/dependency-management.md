# Dependency Management — Trusted PBA

Per [compliance baseline §14](../compliance-and-secure-development-baseline.md)
(dependency & SBOM management) and §19 (supply-chain integrity). Covers the
third-party dependency tree, how it is pinned/verified/scanned, the
security-critical-dependency review gate, and the update flow. The go-boot fork
governance is ADR-0008; this document is the broader policy.

- **Owner:** Architecture Owner (graph + update decisions); Security Owner
  (security-critical-dep gate); Compliance Owner (license/SBOM evidence).
- **Onboarding evidence (this doc's companion artifacts):**
  [`evidence/sbom/`](../../evidence/sbom/) (CycloneDX SBOM snapshot),
  [`evidence/dependency-scans/`](../../evidence/dependency-scans/) (license
  inventory). Regenerated per release.

## 1. The dependency tree

Trusted PBA is a TamaGo (bare-metal Go) UEFI app; its compiled, shipped
dependencies are deliberately small. The packages the `GOOS=tamago` build of
`cmd/pba` actually pulls (the *pruned* graph, `go list -deps ./cmd/pba`):

- **`github.com/walterchris/go-boot`** — `uefi`, `uefi/x64` (the pinned fork; UEFI
  board layer + protocol wrappers + the firmware-ABI call primitive). TCB.
- **`github.com/usbarmory/tamago`** — `amd64`, `dma`, `bits`, `internal/{exception,reg,rng}`,
  `kvm/clock`, `amd64/lapic`, `soc/intel/{rtc,uart}` (the bare-metal Go runtime/SoC).
  TCB.
- **`github.com/foxboron/go-uefi`** — `authenticode`, `pkcs7`, `efi/{signature,attr,
  attributes,fs,util}`, `efivar` (PE/Authenticode + Secure Boot signature parsing,
  used by `internal/imageverify`/`internal/truststore`). Parses attacker-controlled
  bytes → fuzzed (`FuzzVerify`).
- **`github.com/u-root/u-root`** — `pkg/boot/bzimage` (pulled transitively via
  go-boot).

`go.sum` locks **88 modules** (most are transitive build/test deps of
tamago/u-root, not compiled into the product). The full component list is in the
committed CycloneDX SBOM.

## 2. Pinning and integrity

- **Modules:** every dependency is pinned by version in `go.mod` and hash-locked in
  `go.sum`. No floating versions. Bumps are deliberate (§4).
- **TamaGo toolchain:** pinned (`TAMAGO_VERSION` in `Taskfile.yml`) **and
  checksum-verified** — `task toolchain` records the tarball SHA-256
  (`TAMAGO_SHA256`) and verifies it before extracting, failing closed on a
  tampered/changed artifact. (Added after the 2026-06-14 break, where upstream
  re-tagged its releases and an unverified download 404'd; see #9.)
- **go-boot fork:** `github.com/walterchris/go-boot`, pinned by tag
  (`v1.6.2-tpba.4`) + `go.sum`. Governance, the minimal-edit-over-upstream policy,
  the re-base process, and the upstream-submission commitment are in **ADR-0008**.
  On every fork bump the published tag's `go.sum` hash is verified byte-identical
  to the reviewed fork commit.
- **Vendored trust materials:** the Microsoft Secure Boot db/dbx in
  `internal/truststore/materials/` are pinned by upstream commit + per-blob SHA-256
  in `materials/PROVENANCE.md` (not a Go module).

## 3. Automated scanning (CI, every PR)

| Check | Tool | Job | Current result |
|---|---|---|---|
| Known vulnerabilities (reachability) | `govulncheck` | `sast` | 0 *called* vulnerabilities |
| Static security analysis | `gosec`, `staticcheck` | `lint` (golangci-lint) | clean |
| Dependency licenses | `go-licenses check` | `dependency-scan` | all permissive |
| SBOM | `cyclonedx-gomod` | `sbom` | CycloneDX artifact per run |
| Committed secrets | `gitleaks` | `secret-scan` | 0 leaks |

Tool versions are **pinned** (not `@latest`) — supply-chain hygiene. See
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) and #9.

## 4. License posture

All direct and transitive **shipped** dependencies are permissive — **MIT,
BSD-2-Clause, BSD-3-Clause, Apache-2.0** — with **no copyleft/GPL**. The current
inventory is committed under `evidence/dependency-scans/`. `go-licenses check`
gates dependency licenses in CI against its forbidden set.

**Open gap (Owner decision):** the repository has no top-level `LICENSE` file yet,
so `go-licenses` cannot classify the first-party `github.com/walterchris/trusted-pba/*`
packages (reported "Unknown") and the CI check ignores first-party with
`--ignore github.com/walterchris/trusted-pba`. Choosing the product license is a
Product/Compliance Owner decision; once set, drop the `--ignore`.

## 5. Update / review flow

To change a dependency (add, bump, remove):

1. **Deliberate, in a PR** — never a silent/incidental bump (baseline §8.1).
2. Update `go.mod`/`go.sum` via the pinned toolchain; `go mod tidy`.
3. Re-run the scanners (`sast`/`dependency-scan`/`sbom` in CI) and **regenerate the
   SBOM + license inventory** under `evidence/` for a release.
4. **Security-critical-dependency gate:** go-boot and tamago are part of the TCB
   (firmware-ABI, runtime). A bump to either — or any change to the go-boot fork —
   requires a **security review** and, for the fork, the ADR-0008 re-base process
   (re-apply + re-review the small upstream-file edits; re-verify the published
   tag's hash). foxboron/go-uefi (attacker-facing parser) bumps re-run the fuzzers.
5. Record the rationale in the PR; update this doc if the graph/policy changes.

## 6. Confirmed: pruned graph

Verified (`go list -deps ./cmd/pba` under `GOOS=tamago`): only the go-boot
`uefi`/`uefi/x64`, the tamago runtime/SoC packages, foxboron/go-uefi, and
u-root `bzimage` (via go-boot) are compiled into the product — matching the §1
inventory. The remaining `go.sum` modules are transitive build/test dependencies
not linked into `trusted-pba.efi`.
