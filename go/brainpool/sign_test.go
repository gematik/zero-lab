package brainpool

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
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

func TestECDH(t *testing.T) {
	for _, curve := range []elliptic.Curve{P256r1(), P384r1()} {
		key, _ := GenerateKey(curve, rand.Reader)
		peer, _ := GenerateKey(curve, rand.Reader)

		got, err := ECDH(key, &peer.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		wantX, _ := curve.ScalarMult(peer.X, peer.Y, key.D.Bytes())
		if new(big.Int).SetBytes(got).Cmp(wantX) != 0 {
			t.Fatalf("%s: ECDH = %x, want %x", curve.Params().Name, got, wantX)
		}
		if len(got) != (curve.Params().BitSize+7)/8 {
			t.Fatalf("%s: shared secret has %d bytes", curve.Params().Name, len(got))
		}
		back, _ := ECDH(peer, &key.PublicKey)
		if !bytes.Equal(got, back) {
			t.Fatal("ECDH is not symmetric")
		}

		offCurve := &ecdsa.PublicKey{Curve: curve, X: peer.X, Y: new(big.Int).Add(peer.Y, big.NewInt(1))}
		if _, err := ECDH(key, offCurve); err == nil {
			t.Fatal("ECDH accepted an off-curve peer")
		}
	}
	p256, _ := GenerateKey(P256r1(), rand.Reader)
	p384, _ := GenerateKey(P384r1(), rand.Reader)
	if _, err := ECDH(p256, &p384.PublicKey); err == nil {
		t.Fatal("ECDH accepted keys on different curves")
	}
}
