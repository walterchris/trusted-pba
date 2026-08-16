package main

import "testing"

// TestPassphraseBufNoRealloc pins the #124 fix: the console passphrase
// accumulator is pre-allocated to the full line-length cap, so appending up to
// maxPassphraseLen bytes never reallocates the backing array. A reallocation
// would strand an un-scrubbed passphrase-prefix copy the prompter's clear()
// cannot reach — the stranded-secret class the opal layer guards with its
// grow-budget reservation (TestStartSessionReserves). A growing slice that
// reallocates necessarily changes cap, so a stable cap across the appends
// proves the single backing array held every byte.
func TestPassphraseBufNoRealloc(t *testing.T) {
	t.Parallel()
	buf := newPassphraseBuf()
	if cap(buf) < maxPassphraseLen {
		t.Fatalf("accumulator cap %d < maxPassphraseLen %d", cap(buf), maxPassphraseLen)
	}
	c := cap(buf)
	for i := range maxPassphraseLen {
		buf = append(buf, 'x')
		if cap(buf) != c {
			t.Fatalf("backing array reallocated at len %d (cap %d -> %d): a passphrase prefix was stranded un-scrubbed",
				i+1, c, cap(buf))
		}
	}
}
