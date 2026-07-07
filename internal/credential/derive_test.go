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

// labSerial is the real lab drive's 20-byte NVMe serial (#112), used to pin the
// two real-world iteration counts against the same salt so the vectors are
// mutation-proof: changing only the iteration count changes the derived key.
var labSerial = []byte("000060250974A6000025")

// TestSedutilPBKDF2KnownAnswer covers the parameterized primitive (#112) against
// three independently-computed reference vectors. The two labSerial vectors share
// salt + seed + key length and differ only in the iteration count, proving the
// iterations parameter is threaded through (not ignored): 500000 is the value the
// PBA sends by default, 75000 is the older upstream sedutil default.
func TestSedutilPBKDF2KnownAnswer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		seed, salt []byte
		iterations int
		keyLen     int
		wantHex    string
	}{
		{"default 500000 / katSerial", katSeed, katSerial, SedutilPBKDF2Iterations, SedutilPBKDF2KeyLen, katExpectedHex},
		{"lab drive 500000", katSeed, labSerial, 500000, 32, "280a21ec5c5ba4873cd094c881a76289764bed8750703686cfe701ca741cffa7"},
		{"lab drive 75000", katSeed, labSerial, 75000, 32, "9fd48029e7adad6b8daf0b44053433b85d5a4efe428c7c577ffbb44417386578"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want, err := hex.DecodeString(tc.wantHex)
			if err != nil {
				t.Fatalf("decode expected: %v", err)
			}
			// Copy the inputs so the test does not depend on the primitive leaving
			// them intact.
			got, err := SedutilPBKDF2(bytes.Clone(tc.seed), bytes.Clone(tc.salt), tc.iterations, tc.keyLen)
			if err != nil {
				t.Fatalf("SedutilPBKDF2: %v", err)
			}
			if len(got) != tc.keyLen {
				t.Fatalf("derived key length = %d, want %d", len(got), tc.keyLen)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("derived key = %x, want %x", got, want)
			}
		})
	}
}

// TestSedutilPBKDF2FailsClosedOnBadParams covers the #112 defensive guards: a
// non-positive iteration count or key length must never derive a degenerate
// credential, even though the policy layer also validates them.
func TestSedutilPBKDF2FailsClosedOnBadParams(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name             string
		iterations, kLen int
	}{
		{"zero iterations", 0, 32},
		{"negative iterations", -1, 32},
		{"zero key length", 500000, 0},
		{"negative key length", 500000, -8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := SedutilPBKDF2(katSeed, katSerial, tc.iterations, tc.kLen)
			if err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
			if got != nil {
				t.Errorf("%s: want no key on error, got %x", tc.name, got)
			}
		})
	}
}

func TestSedutilPBKDF2FailsClosedOnEmptySeed(t *testing.T) {
	t.Parallel()
	got, err := SedutilPBKDF2(nil, katSerial, SedutilPBKDF2Iterations, SedutilPBKDF2KeyLen)
	if err == nil {
		t.Fatal("empty seed: want error, got nil")
	}
	if got != nil {
		t.Errorf("empty seed must return no key, got %x", got)
	}
	// An empty (non-nil) seed must also fail closed.
	if _, err := SedutilPBKDF2([]byte{}, katSerial, SedutilPBKDF2Iterations, SedutilPBKDF2KeyLen); err == nil {
		t.Error("empty (non-nil) seed: want error, got nil")
	}
}

func TestSedutilPBKDF2FailsClosedOnEmptySalt(t *testing.T) {
	t.Parallel()
	got, err := SedutilPBKDF2(katSeed, nil, SedutilPBKDF2Iterations, SedutilPBKDF2KeyLen)
	if err == nil {
		t.Fatal("empty salt: want error, got nil")
	}
	if got != nil {
		t.Errorf("empty salt must return no key, got %x", got)
	}
	if _, err := SedutilPBKDF2(katSeed, []byte{}, SedutilPBKDF2Iterations, SedutilPBKDF2KeyLen); err == nil {
		t.Error("empty (non-nil) salt: want error, got nil")
	}
}
