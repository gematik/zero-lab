package brainpool

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool/internal/bp256"
)

func fill32(v *big.Int) []byte {
	b := make([]byte, 32)
	v.FillBytes(b)
	return b
}

// Signatures produced by bp256.SignWithNonce must verify under the stdlib ECDSA
// over rcurve (and be low-s).
func TestDiffSignVerifiesUnderStdlib(t *testing.T) {
	key, err := ecdsa.GenerateKey(P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := P256r1().Params().N
	d := fill32(key.D)
	for i := 0; i < 20; i++ {
		msg := []byte{0x01, byte(i), 0xC3}
		h := sha256.Sum256(msg)

		// Random nonce in [1, n-1].
		kBig, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(1)))
		if err != nil {
			t.Fatal(err)
		}
		kBig.Add(kBig, big.NewInt(1))

		r, s, err := bp256.SignWithNonce(d, fill32(kBig), h[:])
		if err != nil {
			t.Fatalf("SignWithNonce: %v", err)
		}
		rBig := new(big.Int).SetBytes(r)
		sBig := new(big.Int).SetBytes(s)
		if !ecdsa.Verify(&key.PublicKey, h[:], rBig, sBig) {
			t.Fatalf("stdlib rejected bp256 signature (i=%d)", i)
		}
		// low-s: s <= n/2.
		if sBig.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
			t.Fatalf("signature is not low-s (i=%d)", i)
		}
	}
}

func TestDiffDeterministicSignVerifies(t *testing.T) {
	key, err := ecdsa.GenerateKey(P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := P256r1().Params().N
	d := fill32(key.D)

	h1 := sha256.Sum256([]byte("message one"))
	h2 := sha256.Sum256([]byte("message two"))

	r1, s1, err := bp256.SignDeterministic(d, h1[:])
	if err != nil {
		t.Fatal(err)
	}
	// Determinism: identical inputs reproduce the identical signature.
	r1b, s1b, _ := bp256.SignDeterministic(d, h1[:])
	if string(r1) != string(r1b) || string(s1) != string(s1b) {
		t.Fatal("RFC 6979 signature is not deterministic")
	}
	// Different message yields a different nonce/signature.
	r2, _, _ := bp256.SignDeterministic(d, h2[:])
	if string(r1) == string(r2) {
		t.Fatal("different messages produced the same r (nonce reuse)")
	}
	// Verifies under stdlib and is low-s.
	if !ecdsa.Verify(&key.PublicKey, h1[:], new(big.Int).SetBytes(r1), new(big.Int).SetBytes(s1)) {
		t.Fatal("deterministic signature did not verify under stdlib")
	}
	if new(big.Int).SetBytes(s1).Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		t.Fatal("deterministic signature is not low-s")
	}
}

func TestDiffECDHMatchesRcurve(t *testing.T) {
	curve := P256r1()
	for _, k := range diffScalars() {
		// peer = m·G for some m.
		mx, my := curve.ScalarBaseMult(big.NewInt(0x9e3779b1).Bytes())
		peer := loadBP(t, mx, my)

		got, err := bp256.ECDH(fill32(k), peer)
		if err != nil {
			t.Fatalf("ECDH: %v", err)
		}
		sx, _ := curve.ScalarMult(mx, my, k.Bytes())
		if new(big.Int).SetBytes(got).Cmp(sx) != 0 {
			t.Fatalf("ECDH x mismatch: got %x want %x", got, sx)
		}
	}
}

func TestDiffECDHSymmetry(t *testing.T) {
	curve := P256r1()
	dA, _ := rand.Int(rand.Reader, curve.Params().N)
	dB, _ := rand.Int(rand.Reader, curve.Params().N)
	dA.Add(dA, big.NewInt(1))
	dB.Add(dB, big.NewInt(1))

	qaX, qaY := curve.ScalarBaseMult(dA.Bytes())
	qbX, qbY := curve.ScalarBaseMult(dB.Bytes())
	qa := loadBP(t, qaX, qaY)
	qb := loadBP(t, qbX, qbY)

	ab, err := bp256.ECDH(fill32(dA), qb)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := bp256.ECDH(fill32(dB), qa)
	if err != nil {
		t.Fatal(err)
	}
	if string(ab) != string(ba) {
		t.Fatal("ECDH not symmetric")
	}
}
