package brainpool

import (
	"math/big"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool/internal/bp256"
)

// This file differential-tests the new constant-time bp256 point arithmetic
// against the trusted (but non-constant-time) rcurve implementation, which is
// the package's pre-existing, real brainpoolP256r1 curve math. rcurve is the
// oracle: any disagreement means the hand-transcribed RCB complete-addition
// formula is wrong.

func diffScalars() []*big.Int {
	out := []*big.Int{
		big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(7),
		big.NewInt(0x1234), big.NewInt(0xDEADBEEF),
	}
	seed, _ := new(big.Int).SetString(
		"6F1E2D3C4B5A69788796A5B4C3D2E1F0123456789ABCDEF0FEDCBA9876543210", 16)
	cur := new(big.Int).Set(seed)
	n := P256r1().Params().N
	for i := 0; i < 10; i++ {
		cur.Mul(cur, seed).Add(cur, big.NewInt(int64(i+1)))
		k := new(big.Int).Mod(cur, n)
		if k.Sign() == 0 {
			k.SetInt64(1)
		}
		out = append(out, k)
	}
	return out
}

// rcurvePoint returns the affine (x,y) of k*G under rcurve, with (nil,nil) for
// the point at infinity.
func rcurvePoint(k *big.Int) (*big.Int, *big.Int) {
	x, y := P256r1().ScalarBaseMult(k.Bytes())
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, nil
	}
	return x, y
}

func uncompressed(x, y *big.Int) []byte {
	buf := make([]byte, 1+2*32)
	buf[0] = 0x04
	x.FillBytes(buf[1:33])
	y.FillBytes(buf[33:])
	return buf
}

func loadBP(t *testing.T, x, y *big.Int) *bp256.Point {
	t.Helper()
	p, err := new(bp256.Point).SetBytes(uncompressed(x, y))
	if err != nil {
		t.Fatalf("bp256.SetBytes(%x,%x): %v", x, y, err)
	}
	return p
}

// bpAffine returns the affine coords of a bp256 point, or (nil,nil) for infinity.
func bpAffine(p *bp256.Point) (*big.Int, *big.Int) {
	enc := p.Bytes()
	if len(enc) == 1 {
		return nil, nil
	}
	return new(big.Int).SetBytes(enc[1:33]), new(big.Int).SetBytes(enc[33:])
}

func assertSamePoint(t *testing.T, ctx string, rx, ry *big.Int, bp *bp256.Point) {
	t.Helper()
	bx, by := bpAffine(bp)
	if rx == nil {
		if bx != nil {
			t.Fatalf("%s: rcurve=infinity, bp256=(%x,%x)", ctx, bx, by)
		}
		return
	}
	if bx == nil {
		t.Fatalf("%s: rcurve=(%x,%x), bp256=infinity", ctx, rx, ry)
	}
	if rx.Cmp(bx) != 0 || ry.Cmp(by) != 0 {
		t.Fatalf("%s: rcurve=(%x,%x) bp256=(%x,%x)", ctx, rx, ry, bx, by)
	}
}

func TestDiffScalarBaseMultPointsLoad(t *testing.T) {
	for _, k := range diffScalars() {
		x, y := rcurvePoint(k)
		if x == nil {
			continue
		}
		// Every rcurve-produced point must validate under bp256 SetBytes.
		assertSamePoint(t, "load k*G", x, y, loadBP(t, x, y))
	}
}

func TestDiffAddMatchesRcurve(t *testing.T) {
	ks := diffScalars()
	curve := P256r1()
	for _, kj := range ks {
		xj, yj := rcurvePoint(kj)
		if xj == nil {
			continue
		}
		for _, kk := range ks {
			xk, yk := rcurvePoint(kk)
			if xk == nil {
				continue
			}
			// rcurve oracle: (kj*G) + (kk*G).
			rx, ry := curve.Add(xj, yj, xk, yk)
			var orx, ory *big.Int
			if !(rx.Sign() == 0 && ry.Sign() == 0) {
				orx, ory = rx, ry
			}
			got := new(bp256.Point).Add(loadBP(t, xj, yj), loadBP(t, xk, yk))
			assertSamePoint(t, "Add", orx, ory, got)
		}
	}
}

func TestDiffDoubleMatchesRcurve(t *testing.T) {
	curve := P256r1()
	for _, k := range diffScalars() {
		x, y := rcurvePoint(k)
		if x == nil {
			continue
		}
		rx, ry := curve.Double(x, y)
		got := new(bp256.Point).Double(loadBP(t, x, y))
		assertSamePoint(t, "Double", rx, ry, got)
	}
}

func TestDiffScalarBaseMultMatchesRcurve(t *testing.T) {
	for _, k := range diffScalars() {
		rx, ry := rcurvePoint(k)
		got := new(bp256.Point).ScalarBaseMult(k.Bytes())
		assertSamePoint(t, "ScalarBaseMult", rx, ry, got)
	}
}

func TestDiffScalarMultMatchesRcurve(t *testing.T) {
	curve := P256r1()
	gx, gy := curve.Params().Gx, curve.Params().Gy
	base := loadBP(t, gx, gy)
	for _, k := range diffScalars() {
		rx, ry := curve.ScalarMult(gx, gy, k.Bytes())
		var orx, ory *big.Int
		if !(rx.Sign() == 0 && ry.Sign() == 0) {
			orx, ory = rx, ry
		}
		got := new(bp256.Point).ScalarMult(base, k.Bytes())
		assertSamePoint(t, "ScalarMult", orx, ory, got)
	}
}

func TestDiffInverseIsInfinity(t *testing.T) {
	curve := P256r1()
	p := P256r1().Params().P
	for _, k := range diffScalars() {
		x, y := rcurvePoint(k)
		if x == nil {
			continue
		}
		negY := new(big.Int).Sub(p, y)
		// rcurve: P + (-P) = infinity, represented (0,0).
		rx, ry := curve.Add(x, y, x, negY)
		if !(rx.Sign() == 0 && ry.Sign() == 0) {
			t.Fatalf("rcurve P+(-P) not infinity: (%x,%x)", rx, ry)
		}
		got := new(bp256.Point).Add(loadBP(t, x, y), loadBP(t, x, negY))
		if got.IsInfinity() != 1 {
			t.Fatal("bp256 P+(-P) not infinity")
		}
	}
}
