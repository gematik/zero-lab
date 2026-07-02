package brainpool

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func p256r1Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// SignFuncPrivateKey on a brainpoolP256r1 key must route through the constant-time
// deterministic (RFC 6979) signer: two signatures over the same hash are equal,
// and they verify under stdlib.
func TestSignFuncPrivateKeyDeterministicForP256r1(t *testing.T) {
	key := p256r1Key(t)
	sign := SignFuncPrivateKey(key)
	h := sha256.Sum256([]byte("bridge determinism"))

	a, err := sign(h[:])
	if err != nil {
		t.Fatal(err)
	}
	b, err := sign(h[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("P256r1 SignFuncPrivateKey is not deterministic (RFC 6979 not applied)")
	}
	if len(a) != 64 {
		t.Fatalf("signature length = %d, want 64", len(a))
	}
	r := new(big.Int).SetBytes(a[:32])
	s := new(big.Int).SetBytes(a[32:])
	if !ecdsa.Verify(&key.PublicKey, h[:], r, s) {
		t.Fatal("bridge signature did not verify under stdlib")
	}
	if s.Cmp(new(big.Int).Rsh(P256r1().Params().N, 1)) > 0 {
		t.Fatal("bridge signature is not low-s")
	}
}

func TestSignFuncPrivateKeyRandomForP256r1(t *testing.T) {
	key := p256r1Key(t)
	sign := SignFuncPrivateKeyRandom(key)
	h := sha256.Sum256([]byte("bridge random"))

	a, _ := sign(h[:])
	b, _ := sign(h[:])
	if bytes.Equal(a, b) {
		t.Fatal("random-nonce signatures should differ")
	}
	for _, sig := range [][]byte{a, b} {
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(&key.PublicKey, h[:], r, s) {
			t.Fatal("random-nonce signature did not verify")
		}
	}
}

func TestECDHP256r1MatchesRcurve(t *testing.T) {
	key := p256r1Key(t)
	peer := p256r1Key(t)

	got, err := ECDHP256r1(key, peer.X, peer.Y)
	if err != nil {
		t.Fatal(err)
	}
	wantX, _ := P256r1().ScalarMult(peer.X, peer.Y, key.D.Bytes())
	if new(big.Int).SetBytes(got).Cmp(wantX) != 0 {
		t.Fatalf("ECDHP256r1 = %x, want %x", got, wantX)
	}

	// Off-curve peer must be rejected.
	if _, err := ECDHP256r1(key, peer.X, new(big.Int).Add(peer.Y, big.NewInt(1))); err == nil {
		t.Fatal("ECDHP256r1 accepted an off-curve peer")
	}
}
