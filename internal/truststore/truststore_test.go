package truststore

import (
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	store, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if store.DB == nil {
		t.Fatal("nil db pool")
	}
	// The dbx amd64 update revokes many image hashes; sanity-check it is non-empty
	// so a parsing regression that silently drops revocations is caught.
	if len(store.DBXHashes) == 0 {
		t.Error("dbx has no revoked image hashes; parse likely failed")
	}
	t.Logf("trust set %q: %d dbx hashes, %d dbx certs", TrustSet, len(store.DBXHashes), len(store.DBXCerts))
}

func TestVerifierWired(t *testing.T) {
	store, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	now := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	v := store.Verifier(now)
	if v.Roots != store.DB || !v.Now.Equal(now) {
		t.Fatal("verifier not wired to store")
	}
}

func TestStripAuth2Rejects(t *testing.T) {
	if _, err := stripAuth2([]byte{0x00}); err == nil {
		t.Error("short update must be rejected")
	}
	// 16-byte EFI_TIME + dwLength claiming more than the buffer holds.
	bad := make([]byte, 20)
	bad[16] = 0xff
	bad[17] = 0xff
	if _, err := stripAuth2(bad); err == nil {
		t.Error("oversized dwLength must be rejected")
	}

	// dwLength between 8 and 24 points into the middle of the WIN_CERTIFICATE
	// header and must be rejected (the cert can never be shorter than 24 bytes).
	short := make([]byte, 64)
	short[16] = 10 // dwLength = 10
	if _, err := stripAuth2(short); err == nil {
		t.Error("dwLength below the 24-byte WIN_CERTIFICATE minimum must be rejected")
	}
}
