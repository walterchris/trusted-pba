package opal

import (
	"bytes"
	"errors"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	uints := []uint64{0, 1, 63, 64, 255, 256, 0xffff, 0x1234567, 0xffffffffffffffff}
	byteStrs := [][]byte{
		{},
		{0xab},
		make([]byte, 15),   // short-atom boundary
		make([]byte, 16),   // medium-atom boundary
		make([]byte, 300),  // medium
		make([]byte, 2048), // long-atom boundary
	}
	for i := range byteStrs {
		for j := range byteStrs[i] {
			byteStrs[i][j] = byte(i*7 + j)
		}
	}

	var b builder
	for _, v := range uints {
		b.uint(v)
	}
	for _, s := range byteStrs {
		b.bytes(s)
	}

	toks, err := tokenize(b.buf)
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	if len(toks) != len(uints)+len(byteStrs) {
		t.Fatalf("got %d tokens, want %d", len(toks), len(uints)+len(byteStrs))
	}
	for i, v := range uints {
		if !toks[i].isInt || toks[i].u != v {
			t.Errorf("uint %d: got %+v", v, toks[i])
		}
	}
	for i, s := range byteStrs {
		tk := toks[len(uints)+i]
		if !tk.isBytes || !bytes.Equal(tk.data, s) {
			t.Errorf("bytes len %d: round-trip mismatch", len(s))
		}
	}
}

func TestTokenControlAndUID(t *testing.T) {
	var b builder
	b.control(tokStartList)
	b.uid(uidMBRControl)
	b.control(tokEndList)

	toks, err := tokenize(b.buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 3 || !toks[0].isControl(tokStartList) || !toks[2].isControl(tokEndList) {
		t.Fatalf("control framing wrong: %+v", toks)
	}
	if !toks[1].isBytes || !bytes.Equal(toks[1].data, uidMBRControl[:]) {
		t.Fatalf("uid atom wrong: %+v", toks[1])
	}
}

func TestTokenizeFailsClosed(t *testing.T) {
	bad := map[string][]byte{
		"short truncated":  {0xA8, 0x01, 0x02},       // claims 8 bytes, has 2
		"medium truncated": {0xD0, 0x10},             // medium header, no body
		"long truncated":   {0xE2, 0x00, 0x00, 0x10}, // claims 16 bytes, has 0
		"reserved token":   {0xE5},
	}
	for name, in := range bad {
		if _, err := tokenize(in); !errors.Is(err, ErrToken) {
			t.Errorf("%s: want ErrToken, got %v", name, err)
		}
	}
}
