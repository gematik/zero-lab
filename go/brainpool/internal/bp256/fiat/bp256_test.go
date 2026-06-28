package fiat

import (
	"bytes"
	"math/big"
	"testing"
)

// p is the brainpoolP256r1 field prime (RFC 5639 §3.4).
var p, _ = new(big.Int).SetString(
	"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16)

func feFromBig(t *testing.T, v *big.Int) *Element {
	t.Helper()
	var buf [ElementLen]byte
	v.FillBytes(buf[:])
	e, err := new(Element).SetBytes(buf[:])
	if err != nil {
		t.Fatalf("SetBytes(%x): %v", buf, err)
	}
	return e
}

func feToBig(e *Element) *big.Int {
	return new(big.Int).SetBytes(e.Bytes())
}

// sample deterministic field values exercising small, large and structured inputs.
func sampleValues(t *testing.T) []*big.Int {
	t.Helper()
	out := []*big.Int{
		big.NewInt(0), big.NewInt(1), big.NewInt(2),
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(p, big.NewInt(2)),
		new(big.Int).Rsh(p, 1),
	}
	seed, _ := new(big.Int).SetString(
		"123456789ABCDEF0FEDCBA98765432100F1E2D3C4B5A69788796A5B4C3D2E1F0", 16)
	cur := new(big.Int).Set(seed)
	for i := 0; i < 32; i++ {
		cur.Mul(cur, seed).Add(cur, big.NewInt(int64(i*2654435761)))
		out = append(out, new(big.Int).Mod(cur, p))
	}
	return out
}

func TestSetBytesBytesRoundTrip(t *testing.T) {
	for _, v := range sampleValues(t) {
		e := feFromBig(t, v)
		if got := feToBig(e); got.Cmp(v) != 0 {
			t.Fatalf("round trip: got %x want %x", got, v)
		}
	}
}

func TestSetBytesRejectsNonCanonical(t *testing.T) {
	bad := [][]byte{}
	// p, p+1, and the maximum 32-byte value are all >= p but still fit in 32
	// bytes (2p does not, so it is not a representable non-canonical encoding).
	for _, v := range []*big.Int{
		p,
		new(big.Int).Add(p, big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
	} {
		var buf [ElementLen]byte
		v.FillBytes(buf[:])
		bad = append(bad, buf[:])
	}
	for _, b := range bad {
		if _, err := new(Element).SetBytes(b); err == nil {
			t.Fatalf("SetBytes(%x) accepted a value >= p", b)
		}
	}
	// wrong length
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := new(Element).SetBytes(make([]byte, n)); err == nil {
			t.Fatalf("SetBytes accepted %d-byte input", n)
		}
	}
}

func TestFieldArithmeticMatchesBigInt(t *testing.T) {
	vals := sampleValues(t)
	for _, a := range vals {
		for _, b := range vals {
			ea, eb := feFromBig(t, a), feFromBig(t, b)

			add := feToBig(new(Element).Add(ea, eb))
			if want := new(big.Int).Mod(new(big.Int).Add(a, b), p); add.Cmp(want) != 0 {
				t.Fatalf("Add(%x,%x)=%x want %x", a, b, add, want)
			}

			sub := feToBig(new(Element).Sub(ea, eb))
			if want := new(big.Int).Mod(new(big.Int).Sub(a, b), p); sub.Cmp(want) != 0 {
				t.Fatalf("Sub(%x,%x)=%x want %x", a, b, sub, want)
			}

			mul := feToBig(new(Element).Mul(ea, eb))
			if want := new(big.Int).Mod(new(big.Int).Mul(a, b), p); mul.Cmp(want) != 0 {
				t.Fatalf("Mul(%x,%x)=%x want %x", a, b, mul, want)
			}
		}
		sq := feToBig(new(Element).Square(feFromBig(t, a)))
		if want := new(big.Int).Mod(new(big.Int).Mul(a, a), p); sq.Cmp(want) != 0 {
			t.Fatalf("Square(%x)=%x want %x", a, sq, want)
		}
	}
}

func TestInvertMatchesBigInt(t *testing.T) {
	for _, v := range sampleValues(t) {
		got := feToBig(new(Element).Invert(feFromBig(t, v)))
		var want *big.Int
		if v.Sign() == 0 {
			want = big.NewInt(0) // Invert(0) == 0 by contract
		} else {
			want = new(big.Int).ModInverse(v, p)
		}
		if got.Cmp(want) != 0 {
			t.Fatalf("Invert(%x)=%x want %x", v, got, want)
		}
	}
}

func TestOneAndEqualAndIsZero(t *testing.T) {
	one := new(Element).One()
	if feToBig(one).Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("One()=%x", feToBig(one))
	}
	if one.IsZero() != 0 {
		t.Fatal("One().IsZero() != 0")
	}
	zero := new(Element)
	if zero.IsZero() != 1 {
		t.Fatal("zero.IsZero() != 1")
	}
	if one.Equal(new(Element).One()) != 1 {
		t.Fatal("One().Equal(One()) != 1")
	}
	if one.Equal(zero) != 0 {
		t.Fatal("One().Equal(zero) != 0")
	}
}

func TestSelect(t *testing.T) {
	a := feFromBig(t, big.NewInt(0x1111))
	b := feFromBig(t, big.NewInt(0x2222))
	if got := new(Element).Select(a, b, 1); !bytes.Equal(got.Bytes(), a.Bytes()) {
		t.Fatal("Select(cond=1) did not pick a")
	}
	if got := new(Element).Select(a, b, 0); !bytes.Equal(got.Bytes(), b.Bytes()) {
		t.Fatal("Select(cond=0) did not pick b")
	}
}
