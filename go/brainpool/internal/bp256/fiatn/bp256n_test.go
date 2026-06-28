package fiatn

import (
	"math/big"
	"testing"
)

// n is the brainpoolP256r1 group order (RFC 5639 §3.4).
var n, _ = new(big.Int).SetString(
	"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16)

func fe(t *testing.T, v *big.Int) *Element {
	t.Helper()
	var buf [ElementLen]byte
	new(big.Int).Mod(v, n).FillBytes(buf[:])
	e, err := new(Element).SetBytes(buf[:])
	if err != nil {
		t.Fatalf("SetBytes: %v", err)
	}
	return e
}

func toBig(e *Element) *big.Int { return new(big.Int).SetBytes(e.Bytes()) }

func samples(t *testing.T) []*big.Int {
	out := []*big.Int{big.NewInt(1), big.NewInt(2), new(big.Int).Sub(n, big.NewInt(1))}
	seed, _ := new(big.Int).SetString(
		"0FEDCBA9876543210123456789ABCDEF6F1E2D3C4B5A69788796A5B4C3D2E1F0", 16)
	cur := new(big.Int).Set(seed)
	for i := 0; i < 24; i++ {
		cur.Mul(cur, seed).Add(cur, big.NewInt(int64(i+3)))
		out = append(out, new(big.Int).Mod(cur, n))
	}
	return out
}

func TestScalarArithmeticMatchesBigInt(t *testing.T) {
	vs := samples(t)
	for _, a := range vs {
		for _, b := range vs {
			ea, eb := fe(t, a), fe(t, b)
			if got, want := toBig(new(Element).Add(ea, eb)), new(big.Int).Mod(new(big.Int).Add(a, b), n); got.Cmp(want) != 0 {
				t.Fatalf("Add: got %x want %x", got, want)
			}
			if got, want := toBig(new(Element).Sub(ea, eb)), new(big.Int).Mod(new(big.Int).Sub(a, b), n); got.Cmp(want) != 0 {
				t.Fatalf("Sub: got %x want %x", got, want)
			}
			if got, want := toBig(new(Element).Mul(ea, eb)), new(big.Int).Mod(new(big.Int).Mul(a, b), n); got.Cmp(want) != 0 {
				t.Fatalf("Mul: got %x want %x", got, want)
			}
		}
	}
}

func TestScalarInvertMatchesBigInt(t *testing.T) {
	for _, v := range samples(t) {
		got := toBig(new(Element).Invert(fe(t, v)))
		want := new(big.Int).ModInverse(v, n)
		if got.Cmp(want) != 0 {
			t.Fatalf("Invert(%x): got %x want %x", v, got, want)
		}
	}
}

func TestScalarSetBytesRejectsGteN(t *testing.T) {
	for _, v := range []*big.Int{
		n,
		new(big.Int).Add(n, big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
	} {
		var buf [ElementLen]byte
		v.FillBytes(buf[:])
		if _, err := new(Element).SetBytes(buf[:]); err == nil {
			t.Fatalf("SetBytes accepted value >= n: %x", buf)
		}
	}
}
