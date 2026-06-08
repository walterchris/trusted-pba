// Package opal implements the TCG Opal SSC protocol logic for unlocking a
// self-encrypting drive, and a native fake drive (MockTPer) to test it.
//
// The protocol logic is byte-faithful — it produces and parses the real TCG
// Storage wire format (Level 0 Discovery, ComPacket/Packet/SubPacket framing, the
// method/token stream, and the Opal UID/column constants) — so the streams it
// emits are accepted by real hardware. It depends only on the abstract Transport
// interface (the plan's TCGTransport), never on UEFI, so it is fully host-testable;
// the UEFI Storage Security and hardware transports live in internal/transport
// (Phase 5+). See ADR-0004 and docs/test-tooling-plan.md §3.
//
// Every device-facing parser fails closed and never panics on malformed input
// (fuzzed; see FuzzResponseParse). The length-field bounds checks assume a 64-bit
// int (the product's only target is GOARCH=amd64); on a 32-bit build a uint32
// length could wrap when converted to int and weaken those guards.
package opal
