package opal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// TCG Storage stream encoding — control tokens (TCG Storage Architecture Core
// Specification §3.2.2). The method/result streams are sequences of "atoms"
// (integers and byte strings) bracketed by these control tokens.
const (
	tokStartList        = 0xF0
	tokEndList          = 0xF1
	tokStartName        = 0xF2
	tokEndName          = 0xF3
	tokCall             = 0xF8
	tokEndOfData        = 0xF9
	tokEndOfSession     = 0xFA
	tokStartTransaction = 0xFB
	tokEndTransaction   = 0xFC
	tokEmpty            = 0xFF
)

// ErrToken is returned for any malformed token stream. Callers must fail closed.
var ErrToken = errors.New("opal: malformed token stream")

// u32 narrows a wire-bounded value to uint32. TCG length and session-id fields are
// 32-bit on the wire and our payloads are bounded by recvBufSize, so this cannot
// overflow in practice; centralizing it documents that intent.
func u32[T int | uint64](v T) uint32 { return uint32(v) } //nolint:gosec // bounded TCG wire value

// lo8 returns the low byte of a bounded length component.
func lo8(v int) byte { return byte(v) } //nolint:gosec // low byte of a bounded length

// builder accumulates a TCG token stream.
type builder struct{ buf []byte }

func (b *builder) control(tok byte) { b.buf = append(b.buf, tok) }

// grow ensures capacity for at least n more bytes so that subsequent appends up
// to that size cannot reallocate the backing array. Call it before encoding
// secret-bearing atoms: a reallocation after the secret is written would strand
// a stale copy in an unreachable array that zeroize can no longer reach.
func (b *builder) grow(n int) { b.buf = slices.Grow(b.buf, n) }

// uint appends an unsigned integer atom using the shortest encoding.
func (b *builder) uint(v uint64) {
	if v < 0x40 { // tiny atom
		b.buf = append(b.buf, byte(v))
		return
	}
	b.atom(minBE(v), false)
}

// bytes appends a byte-string atom.
func (b *builder) bytes(d []byte) { b.atom(d, true) }

// uid appends an 8-byte UID as a byte-string atom.
func (b *builder) uid(u UID) { b.atom(u[:], true) }

// atom appends a (non-tiny) simple atom. isBytes selects byte-string vs integer;
// both are unsigned (sign bit clear).
func (b *builder) atom(d []byte, isBytes bool) {
	var bbit byte
	if isBytes {
		bbit = 1
	}
	n := len(d)
	switch {
	case n <= 15: // short atom: 0b10 B S LLLL
		b.buf = append(b.buf, 0x80|(bbit<<5)|byte(n))
	case n <= 2047: // medium atom: 0b110 B S + 11-bit length
		b.buf = append(b.buf, 0xC0|(bbit<<4)|lo8((n>>8)&0x07), lo8(n))
	default: // long atom: 0b1110 00 B S + 24-bit length
		b.buf = append(b.buf, 0xE0|(bbit<<1), lo8(n>>16), lo8(n>>8), lo8(n))
	}
	b.buf = append(b.buf, d...)
}

// minBE returns v as big-endian bytes with leading zero bytes stripped (>=1 byte).
func minBE(v uint64) []byte {
	var full [8]byte
	binary.BigEndian.PutUint64(full[:], v)
	i := 0
	for i < 7 && full[i] == 0 {
		i++
	}
	return full[i:]
}

// token is one decoded stream element: either a control token (ctrl != 0) or a
// simple atom (an integer or a byte string).
type token struct {
	ctrl    byte
	isInt   bool
	isBytes bool
	u       uint64
	data    []byte
}

func (t token) isControl(c byte) bool { return t.ctrl == c }

// tokenize decodes a complete TCG token stream into a flat token slice. It fails
// closed on any truncation or reserved/unsupported encoding.
func tokenize(data []byte) ([]token, error) {
	var out []token
	for i := 0; i < len(data); {
		b0 := data[i]
		switch {
		case b0 < 0x80: // tiny atom (also covers values 0..63)
			out = append(out, token{isInt: true, u: uint64(b0 & 0x3f)})
			i++
		case b0 < 0xC0: // short atom
			n := int(b0 & 0x0f)
			isBytes := b0&0x20 != 0
			if i+1+n > len(data) {
				return nil, fmt.Errorf("%w: short atom truncated", ErrToken)
			}
			out = append(out, atomToken(data[i+1:i+1+n], isBytes))
			i += 1 + n
		case b0 < 0xE0: // medium atom
			if i+2 > len(data) {
				return nil, fmt.Errorf("%w: medium header truncated", ErrToken)
			}
			n := int(b0&0x07)<<8 | int(data[i+1])
			isBytes := b0&0x10 != 0
			if i+2+n > len(data) {
				return nil, fmt.Errorf("%w: medium atom truncated", ErrToken)
			}
			out = append(out, atomToken(data[i+2:i+2+n], isBytes))
			i += 2 + n
		case b0 < 0xE4: // long atom
			if i+4 > len(data) {
				return nil, fmt.Errorf("%w: long header truncated", ErrToken)
			}
			n := int(data[i+1])<<16 | int(data[i+2])<<8 | int(data[i+3])
			isBytes := b0&0x02 != 0
			if i+4+n > len(data) {
				return nil, fmt.Errorf("%w: long atom truncated", ErrToken)
			}
			out = append(out, atomToken(data[i+4:i+4+n], isBytes))
			i += 4 + n
		case b0 >= 0xF0: // control token
			out = append(out, token{ctrl: b0})
			i++
		default: // 0xE4..0xEF reserved
			return nil, fmt.Errorf("%w: reserved token 0x%02x", ErrToken, b0)
		}
	}
	return out, nil
}

// atomToken builds a token from raw atom bytes, decoding integers big-endian.
func atomToken(d []byte, isBytes bool) token {
	if isBytes {
		return token{isBytes: true, data: d}
	}
	var v uint64
	for _, c := range d {
		v = v<<8 | uint64(c)
	}
	return token{isInt: true, u: v}
}
