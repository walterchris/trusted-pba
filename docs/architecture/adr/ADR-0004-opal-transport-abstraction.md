# ADR-0004: Opal protocol logic / transport abstraction

## Status
Accepted — §5.3/§23 human gate satisfied by the Release Owner merging the Phase 4
PR (this ADR + `internal/opal`). Supersedes the placeholder reference to ADR-0004 in
the compliance baseline's repo layout. (Authored in Phase 4; the foundational-ADR
backlog item #8 is partially discharged by this.)

## Context
The product goal (plan §3) is for the PBA to unlock a TCG Opal SED and then
chainload the OS. Opal is a byte-level protocol (Level 0 Discovery,
ComPacket/Packet/SubPacket framing, a method/token stream, fixed object/method
UIDs). It must run over several carriers over the product's life: a native mock
(tests), the UEFI `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL` (Phase 5), and real
SATA/NVMe hardware (Phase 8). CLAUDE.md and plan §4.3 require the Opal logic to be
**separated from transport** and testable without UEFI.

## Decision

### 1. Transport abstraction
The Opal logic depends only on a small interface (the plan's `TCGTransport`),
defined where it is consumed (package `opal`):
```go
type Transport interface {
    Send(proto uint8, comID uint16, data []byte) error
    Recv(proto uint8, comID uint16, size int) ([]byte, error)
}
```
`proto`/`comID` mirror the UEFI Storage Security protocol's SecurityProtocol +
SP-Specific arguments, so the real Phase 5 transport is a thin adapter. The Opal
logic never imports UEFI; it is pure Go and host-testable.

### 2. Byte-faithful wire format
The Opal logic produces and parses the **real** TCG Storage wire format — token
encoding, ComPacket/Packet/SubPacket framing, Level 0 Discovery feature
descriptors, and the Opal UID/column constants (byte-identical to the TCG Opal SSC
and the Linux kernel `sed-opal` table). The streams it emits are therefore
accepted by real drives, so the protocol logic carries over to Phases 5/8 with
minimal rework. (Chosen over a simplified internal encoding precisely to avoid that
rework and to make the golden fixtures meaningful for real hardware.)

### 3. Native fake drive (MockTPer)
`opal.MockTPer` is a fake TPer implementing `Transport`: it decodes the packets and
methods the client sends and emits real Discovery0 / SyncSession / method-result
streams, maintaining device state (locked, MBR enabled/done) and the Admin1
credential, with injectable faults (timeout, malformed response). It lives in
package `opal` — not the plan's `internal/transport/mock.go` — because it is
protocol-aware and shares the package's unexported codec; exporting the codec just
to relocate the mock would be worse. `internal/transport` holds the thin,
codec-free real carriers (UEFI in Phase 5+).

### 4. Shared golden fixtures
The Go simulator and the EDK2 `MockOpalDxe` (C, Phase 6) cannot share code, so they
share a spec + byte-exact golden fixtures (`test/fixtures/opal/`), treated as the
source of truth. `TestDiscoveryGoldenFixture` locks the format.

### 5. Unlock flow & scope
MVP unlock: Level 0 Discovery → StartSession on the Locking SP authenticating
Admin1 via HostChallenge → clear the global range read/write locks → set MBRDone
(if a shadow MBR is shadowing) → EndOfSession. Authentication is a credential check
(no block crypto, per the plan); individual locking ranges and the Admin SP
provisioning flow are out of scope for Phase 4 (the structure extends to them).

## Alternatives Considered
- **Simplified internal encoding** between logic and mock — faster, but the
  command-emitting code would be rewritten for real hardware and the fixtures would
  not reflect real drives. Rejected.
- **Hardcode UEFI into the Opal logic** — violates the separation rule; untestable
  without QEMU. Rejected.
- **Mock in `internal/transport`** — would require exporting the low-level codec.
  Rejected in favor of co-locating the protocol-aware mock with the codec.

## Security Impact
The unlock path is security-critical: it must **fail closed** — any failure of
discovery, authentication, status, or transport aborts and the drive stays locked
(the PBA must not chainload). Every device-facing parser (tokens, packets,
discovery, method results) fails closed and never panics on malformed/attacker
input — exercised by `FuzzResponseParse`. Wrong credential, unsupported feature,
invalid ComID, malformed response, and timeout are all covered by negative tests
and keep the drive locked. No unlock material is logged. New risk surface (Opal
response parsing, unlock sequencing) maps to risk-assessment R-002/R-003/R-009 and
the threat model's malicious-EFL/real-drive items; those must be updated as the SED
unlock asset moves from *planned* to *implemented*.

## Compliance Impact
Advances CRA "integrity"/"secure by default" (the PBA controls SED unlock). §5.3
human gate (boot-chain/unlock behavior) + §23 ADR satisfied by approving this. No
new third-party dependency (pure stdlib + the existing module). Parser fuzzing
satisfies baseline §12 ("fuzz TCG Opal response parsing").

## Test Impact
Host unit tests for the full unlock flow + the negative matrix (wrong password,
unsupported feature, invalid ComID, malformed response, timeout, unknown
authority); token/packet/discovery round-trip + fail-closed tests; a byte-exact
Discovery0 golden fixture; and `FuzzResponseParse` over the device-response path
(wired into the CI fuzz-smoke job). AC: `go test ./...` passes; builds under TamaGo.

## Rollback Plan
`internal/opal` and `test/fixtures/opal` are additive; nothing in the shipped boot
path depends on them yet (wiring is Phase 5/6). Reverting the Phase 4 PR removes the
package with no effect on the Phase 1–3 boot manager.
