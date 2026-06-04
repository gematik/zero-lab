package vau

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// makeTestChannel constructs a Channel with deterministic key material so the
// snapshot/restore tests don't depend on a live handshake.
func makeTestChannel(t *testing.T, requestCounter, ivCounter uint64) *Channel {
	t.Helper()
	u, err := url.Parse("https://example.invalid/VAU-test")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	return &Channel{
		httpClient:              &http.Client{},
		Env:                     EnvNonPU,
		ID:                      "test-channel-id",
		ChannelURL:              u,
		keyID:                   bytes.Repeat([]byte{0xA1}, 32),
		k2_c2s_app_data:         bytes.Repeat([]byte{0xB2}, 32),
		k2_c2s_app_data_counter: Counter{value: ivCounter},
		k2_s2c_app_data:         bytes.Repeat([]byte{0xC3}, 32),
		requestCounter:          Counter{value: requestCounter},
	}
}

func TestSnapshotPreservesFields(t *testing.T) {
	c := makeTestChannel(t, 17, 99)
	snap := c.Snapshot()

	if snap.Env != EnvNonPU {
		t.Errorf("Env: got %d, want %d", snap.Env, EnvNonPU)
	}
	if snap.ID != "test-channel-id" {
		t.Errorf("ID: got %q", snap.ID)
	}
	if snap.ChannelURL != "https://example.invalid/VAU-test" {
		t.Errorf("ChannelURL: got %q", snap.ChannelURL)
	}
	if !bytes.Equal(snap.KeyID, bytes.Repeat([]byte{0xA1}, 32)) {
		t.Errorf("KeyID mismatch")
	}
	if !bytes.Equal(snap.K2C2SAppData, bytes.Repeat([]byte{0xB2}, 32)) {
		t.Errorf("K2C2SAppData mismatch")
	}
	if !bytes.Equal(snap.K2S2CAppData, bytes.Repeat([]byte{0xC3}, 32)) {
		t.Errorf("K2S2CAppData mismatch")
	}
	if snap.RequestCounter != 17 {
		t.Errorf("RequestCounter: got %d, want 17", snap.RequestCounter)
	}
	if snap.K2C2SAppDataCounter != 99 {
		t.Errorf("K2C2SAppDataCounter: got %d, want 99", snap.K2C2SAppDataCounter)
	}
}

func TestSnapshotIsADefensiveCopy(t *testing.T) {
	c := makeTestChannel(t, 0, 0)
	snap := c.Snapshot()

	// Mutating the snapshot bytes must not affect the channel.
	snap.KeyID[0] = 0xFF
	snap.K2C2SAppData[0] = 0xFF
	snap.K2S2CAppData[0] = 0xFF

	if c.keyID[0] != 0xA1 || c.k2_c2s_app_data[0] != 0xB2 || c.k2_s2c_app_data[0] != 0xC3 {
		t.Fatal("Snapshot leaked a reference to internal key bytes")
	}
}

func TestRestoreRoundtripsAllFields(t *testing.T) {
	original := makeTestChannel(t, 42, 7)
	snap := original.Snapshot()

	restored, err := RestoreChannel(snap, &http.Client{})
	if err != nil {
		t.Fatalf("RestoreChannel: %v", err)
	}

	if restored.Env != original.Env {
		t.Errorf("Env mismatch")
	}
	if restored.ID != original.ID {
		t.Errorf("ID mismatch")
	}
	if restored.ChannelURL.String() != original.ChannelURL.String() {
		t.Errorf("URL mismatch")
	}
	if !bytes.Equal(restored.keyID, original.keyID) {
		t.Errorf("keyID mismatch")
	}
	if !bytes.Equal(restored.k2_c2s_app_data, original.k2_c2s_app_data) {
		t.Errorf("k2_c2s_app_data mismatch")
	}
	if !bytes.Equal(restored.k2_s2c_app_data, original.k2_s2c_app_data) {
		t.Errorf("k2_s2c_app_data mismatch")
	}
	if restored.requestCounter.value != 42 {
		t.Errorf("requestCounter: got %d, want 42", restored.requestCounter.value)
	}
	if restored.k2_c2s_app_data_counter.value != 7 {
		t.Errorf("k2_c2s_app_data_counter: got %d, want 7", restored.k2_c2s_app_data_counter.value)
	}
}

func TestRestoredChannelAdvancesCountersFromState(t *testing.T) {
	original := makeTestChannel(t, 5, 200)
	snap := original.Snapshot()
	restored, err := RestoreChannel(snap, &http.Client{})
	if err != nil {
		t.Fatalf("RestoreChannel: %v", err)
	}

	enc, err := restored.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The request counter on the wire MUST start at state+1; reusing 5 would
	// be a server-side replay reject (and reusing the IV would break AES-GCM
	// nonce uniqueness).
	if enc.RequestCounter != 6 {
		t.Errorf("first request counter after restore: got %d, want 6", enc.RequestCounter)
	}
	// Header[3:11] is the request counter big-endian.
	gotCounter := binary.BigEndian.Uint64(enc.Ciphertext[3:11])
	if gotCounter != 6 {
		t.Errorf("header request counter: got %d, want 6", gotCounter)
	}
	// Header[11:43] is keyID.
	if !bytes.Equal(enc.Ciphertext[11:43], snap.KeyID) {
		t.Errorf("header keyID does not match restored state")
	}
}

func TestRestoredChannelCiphertextDecryptsWithSameKey(t *testing.T) {
	// Build two channels with identical state; one fresh, one restored. Their
	// outputs at the same starting counter should be byte-equivalent except
	// for the random 4-byte IV prefix. We round-trip the plaintext through
	// AES-GCM with the snapshot's key to prove the AEAD construction wasn't
	// disturbed by Restore.
	c := makeTestChannel(t, 0, 0)
	snap := c.Snapshot()
	restored, err := RestoreChannel(snap, &http.Client{})
	if err != nil {
		t.Fatalf("RestoreChannel: %v", err)
	}

	plaintext := []byte("test payload for vau restore")
	enc, err := restored.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Decrypt manually using the snapshot's key to confirm it round-trips.
	aesBlock, err := aes.NewCipher(snap.K2C2SAppData)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	header := enc.Ciphertext[:43]
	body := enc.Ciphertext[43:]
	iv := body[:12]
	ciphertext := body[12:]
	got, err := gcm.Open(nil, iv, ciphertext, header)
	if err != nil {
		t.Fatalf("AEAD decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted plaintext mismatch")
	}
}

func TestRestoreRejectsNilHTTPClient(t *testing.T) {
	c := makeTestChannel(t, 0, 0)
	if _, err := RestoreChannel(c.Snapshot(), nil); err == nil {
		t.Fatal("expected error for nil http client")
	}
}

func TestRestoreRejectsMissingKeyMaterial(t *testing.T) {
	cases := []struct {
		name  string
		mutate func(s *ChannelSnapshot)
	}{
		{"no KeyID", func(s *ChannelSnapshot) { s.KeyID = nil }},
		{"no K2C2S", func(s *ChannelSnapshot) { s.K2C2SAppData = nil }},
		{"no K2S2C", func(s *ChannelSnapshot) { s.K2S2CAppData = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := makeTestChannel(t, 0, 0)
			s := c.Snapshot()
			tc.mutate(&s)
			if _, err := RestoreChannel(s, &http.Client{}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRestoreRejectsBadURL(t *testing.T) {
	c := makeTestChannel(t, 0, 0)
	s := c.Snapshot()
	s.ChannelURL = "://bad-url"
	if _, err := RestoreChannel(s, &http.Client{}); err == nil {
		t.Fatal("expected error for bad URL")
	}
}

func TestChannelSnapshotJSONRoundtrip(t *testing.T) {
	c := makeTestChannel(t, 123, 456)
	snap := c.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var got ChannelSnapshot
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	restored, err := RestoreChannel(got, &http.Client{})
	if err != nil {
		t.Fatalf("RestoreChannel after JSON: %v", err)
	}
	if restored.requestCounter.value != 123 || restored.k2_c2s_app_data_counter.value != 456 {
		t.Fatalf("counters lost across JSON roundtrip: req=%d iv=%d",
			restored.requestCounter.value, restored.k2_c2s_app_data_counter.value)
	}
	if !bytes.Equal(restored.keyID, snap.KeyID) {
		t.Fatalf("keyID lost across JSON roundtrip")
	}
}
