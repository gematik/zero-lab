package proxy

import (
	"bytes"
	"testing"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestRecordCipherRoundTrip(t *testing.T) {
	c, err := newAESRecordCrypter(testKey(7))
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte(`{"id":"s1","access_token":"super-secret"}`)
	ct, err := c.seal(pt, []byte("s1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("super-secret")) {
		t.Fatal("ciphertext leaks plaintext (not encrypted)")
	}
	got, err := c.open(ct, []byte("s1"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestRecordCipherRejectsTamper(t *testing.T) {
	c, _ := newAESRecordCrypter(testKey(7))
	ct, _ := c.seal([]byte("hello"), []byte("s1"))
	ct[len(ct)-1] ^= 0xff // flip a ciphertext byte
	if _, err := c.open(ct, []byte("s1")); err == nil {
		t.Fatal("tampered ciphertext accepted (no integrity)")
	}
}

func TestRecordCipherRejectsSubstitution(t *testing.T) {
	c, _ := newAESRecordCrypter(testKey(7))
	// A rogue storage admin copies session A's record onto session B's key.
	ct, _ := c.seal([]byte("session A record"), []byte("sessionA"))
	if _, err := c.open(ct, []byte("sessionB")); err == nil {
		t.Fatal("record opened under a different key (substitution not prevented by AAD binding)")
	}
}

func TestRecordCipherRejectsWrongKey(t *testing.T) {
	a, _ := newAESRecordCrypter(testKey(7))
	b, _ := newAESRecordCrypter(testKey(9))
	ct, _ := a.seal([]byte("x"), []byte("s1"))
	if _, err := b.open(ct, []byte("s1")); err == nil {
		t.Fatal("record opened with the wrong key")
	}
}

func TestNewRecordCipherRejectsShortKey(t *testing.T) {
	if _, err := newAESRecordCrypter(make([]byte, 16)); err == nil {
		t.Fatal("accepted a 16-byte key (must require 32 for AES-256)")
	}
}
