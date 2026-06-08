package opal

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TCG Storage transport framing: a payload (token stream) is wrapped in a
// SubPacket, a Packet, and a ComPacket (TCG Storage Architecture Core Spec §3.3).
// Header sizes are fixed and match the Linux kernel's sed-opal layout.
const (
	comPacketHdrLen = 20
	packetHdrLen    = 24
	subPacketHdrLen = 12
	frameHdrLen     = comPacketHdrLen + packetHdrLen + subPacketHdrLen // 56
	subPacketKind   = 0x0000                                           // data subpacket
)

// ErrPacket is returned for malformed transport framing. Fail closed.
var ErrPacket = errors.New("opal: malformed packet framing")

// roundUp4 rounds n up to the next multiple of 4 (TCG payloads are 4-byte aligned).
func roundUp4(n int) int { return (n + 3) &^ 3 }

// encodePacket wraps a token-stream payload in the SubPacket/Packet/ComPacket
// headers for the given ComID and session (tsn/hsn are 0 before a session exists).
func encodePacket(comID uint16, tsn, hsn uint32, payload []byte) []byte {
	padded := roundUp4(len(payload))
	buf := make([]byte, frameHdrLen+padded)

	// ComPacket header (offset 0): reserved(4), extendedComID(4), outstanding(4),
	// minTransfer(4), length(4).
	binary.BigEndian.PutUint16(buf[4:], comID)
	binary.BigEndian.PutUint32(buf[16:], u32(packetHdrLen+subPacketHdrLen+padded))

	// Packet header (offset 20): tsn(4), hsn(4), seq(4), reserved(2), ackType(2),
	// ack(4), length(4).
	binary.BigEndian.PutUint32(buf[20:], tsn)
	binary.BigEndian.PutUint32(buf[24:], hsn)
	binary.BigEndian.PutUint32(buf[40:], u32(subPacketHdrLen+padded))

	// SubPacket header (offset 44): reserved(6), kind(2), length(4).
	binary.BigEndian.PutUint16(buf[50:], subPacketKind)
	binary.BigEndian.PutUint32(buf[52:], u32(len(payload))) // unpadded

	copy(buf[frameHdrLen:], payload)
	return buf
}

// decodePacket extracts the token-stream payload from a received frame, validating
// the nested length fields. It fails closed on any inconsistency or truncation.
func decodePacket(data []byte) ([]byte, error) {
	if len(data) < frameHdrLen {
		return nil, fmt.Errorf("%w: short frame (%d bytes)", ErrPacket, len(data))
	}
	comLen := int(binary.BigEndian.Uint32(data[16:]))
	if comLen+comPacketHdrLen > len(data) {
		return nil, fmt.Errorf("%w: comPacket length %d exceeds frame", ErrPacket, comLen)
	}
	if comLen == 0 {
		return nil, nil // empty response (e.g. a bare ack)
	}
	// pktLen counts the SubPacket header + padded payload; it must fit in the
	// ComPacket section.
	pktLen := int(binary.BigEndian.Uint32(data[40:]))
	if pktLen < subPacketHdrLen || packetHdrLen+pktLen > comLen {
		return nil, fmt.Errorf("%w: packet length %d inconsistent with comPacket %d", ErrPacket, pktLen, comLen)
	}
	// subLen is the unpadded payload; it must fit in the SubPacket section.
	subLen := int(binary.BigEndian.Uint32(data[52:]))
	if subLen > pktLen-subPacketHdrLen || frameHdrLen+subLen > len(data) {
		return nil, fmt.Errorf("%w: subPacket length %d inconsistent", ErrPacket, subLen)
	}
	return data[frameHdrLen : frameHdrLen+subLen], nil
}
