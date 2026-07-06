package credential

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// katSerial is a fixed 20-byte, space-padded serial standing in for a drive's
// serial number (the PBKDF2 salt). It is exactly 20 bytes as sedutil supplies it.
var katSerial = []byte("S3EMNX0M12345678    ")

// katSeed is the fixed unlock seed (the shared-spec test passphrase).
var katSeed = []byte("correct horse")

// katExpectedHex is the known-answer PBKDF2-HMAC-SHA512 output for
// (katSeed, katSerial, 500000, 32), computed independently with the reference
// implementation:
//
//	python3 -c "import hashlib; print(hashlib.pbkdf2_hmac('sha512', \
//	  b'correct horse', b'S3EMNX0M12345678    ', 500000, 32).hex())"
//
// which is bit-identical to sedutil's cf_pbkdf2_hmac + cf_sha512 for the same
// inputs. If SedutilPBKDF2's algorithm or defaults drift, this vector breaks.
const katExpectedHex = "cb7d0c57899ad13070a65e49a7eceed1461f3ae141c255a792c0e5b6e7d137e7"

func TestSedutilPBKDF2KnownAnswer(t *testing.T) {
	t.Parallel()
	want, err := hex.DecodeString(katExpectedHex)
	if err != nil {
		t.Fatalf("decode expected: %v", err)
	}
	// Copy the inputs so the test does not depend on the primitive leaving them
	// intact.
	got, err := SedutilPBKDF2(bytes.Clone(katSeed), bytes.Clone(katSerial))
	if err != nil {
		t.Fatalf("SedutilPBKDF2: %v", err)
	}
	if len(got) != SedutilPBKDF2KeyLen {
		t.Fatalf("derived key length = %d, want %d", len(got), SedutilPBKDF2KeyLen)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("derived key = %x, want %x", got, want)
	}
}

func TestSedutilPBKDF2FailsClosedOnEmptySeed(t *testing.T) {
	t.Parallel()
	got, err := SedutilPBKDF2(nil, katSerial)
	if err == nil {
		t.Fatal("empty seed: want error, got nil")
	}
	if got != nil {
		t.Errorf("empty seed must return no key, got %x", got)
	}
	// An empty (non-nil) seed must also fail closed.
	if _, err := SedutilPBKDF2([]byte{}, katSerial); err == nil {
		t.Error("empty (non-nil) seed: want error, got nil")
	}
}

func TestSedutilPBKDF2FailsClosedOnEmptySalt(t *testing.T) {
	t.Parallel()
	got, err := SedutilPBKDF2(katSeed, nil)
	if err == nil {
		t.Fatal("empty salt: want error, got nil")
	}
	if got != nil {
		t.Errorf("empty salt must return no key, got %x", got)
	}
	if _, err := SedutilPBKDF2(katSeed, []byte{}); err == nil {
		t.Error("empty (non-nil) salt: want error, got nil")
	}
}
