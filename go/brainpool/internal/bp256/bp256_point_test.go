package bp256

import (
	"bytes"
	"testing"
)

func mustGen(t *testing.T) *Point {
	t.Helper()
	return new(Point).SetGenerator()
}

func affine(t *testing.T, p *Point) []byte {
	t.Helper()
	return p.Bytes()
}

func TestGeneratorRoundTrip(t *testing.T) {
	g := mustGen(t)
	enc := g.Bytes()
	if len(enc) != uncompressedLen || enc[0] != uncompressedTag {
		t.Fatalf("generator encoding malformed: %x", enc)
	}
	back, err := new(Point).SetBytes(enc)
	if err != nil {
		t.Fatalf("SetBytes(generator): %v", err)
	}
	if !bytes.Equal(back.Bytes(), enc) {
		t.Fatal("generator round trip mismatch")
	}
}

func TestInfinityEncoding(t *testing.T) {
	inf := NewPoint()
	if inf.IsInfinity() != 1 {
		t.Fatal("NewPoint is not infinity")
	}
	enc := inf.Bytes()
	if !bytes.Equal(enc, []byte{0}) {
		t.Fatalf("infinity encoding = %x, want 00", enc)
	}
	back, err := new(Point).SetBytes(enc)
	if err != nil {
		t.Fatalf("SetBytes(infinity): %v", err)
	}
	if back.IsInfinity() != 1 {
		t.Fatal("infinity did not round trip")
	}
	if _, err := inf.BytesX(); err == nil {
		t.Fatal("BytesX on infinity should error")
	}
}

func TestAddIdentity(t *testing.T) {
	g := mustGen(t)
	inf := NewPoint()

	if got := new(Point).Add(g, inf); !bytes.Equal(affine(t, got), affine(t, g)) {
		t.Fatal("G + O != G")
	}
	if got := new(Point).Add(inf, g); !bytes.Equal(affine(t, got), affine(t, g)) {
		t.Fatal("O + G != G")
	}
	if got := new(Point).Add(inf, inf); got.IsInfinity() != 1 {
		t.Fatal("O + O != O")
	}
}

func TestAddInverseIsInfinity(t *testing.T) {
	g := mustGen(t)
	negG := new(Point).Negate(g)
	if got := new(Point).Add(g, negG); got.IsInfinity() != 1 {
		t.Fatal("G + (-G) != O")
	}
}

func TestDoubleMatchesSelfAdd(t *testing.T) {
	g := mustGen(t)
	d := new(Point).Double(g)
	s := new(Point).Add(g, g)
	if !bytes.Equal(affine(t, d), affine(t, s)) {
		t.Fatal("Double(G) != G + G")
	}
	if d.IsInfinity() == 1 {
		t.Fatal("2G should not be infinity")
	}
	// (2G) + (-G) == G
	twoG := new(Point).Double(g)
	negG := new(Point).Negate(g)
	back := new(Point).Add(twoG, negG)
	if !bytes.Equal(affine(t, back), affine(t, g)) {
		t.Fatal("2G + (-G) != G")
	}
}

func TestAddCommutative(t *testing.T) {
	g := mustGen(t)
	twoG := new(Point).Double(g)
	a := new(Point).Add(g, twoG)
	b := new(Point).Add(twoG, g)
	if !bytes.Equal(affine(t, a), affine(t, b)) {
		t.Fatal("G + 2G != 2G + G")
	}
}

func TestAddAssociative(t *testing.T) {
	g := mustGen(t)
	// (G + G) + G == G + (G + G)
	left := new(Point).Add(new(Point).Add(g, g), g)
	right := new(Point).Add(g, new(Point).Add(g, g))
	if !bytes.Equal(affine(t, left), affine(t, right)) {
		t.Fatal("(G+G)+G != G+(G+G)")
	}
}

func TestSetBytesRejectsBadPoints(t *testing.T) {
	g := mustGen(t).Bytes()

	// Flip a coordinate bit so the point is off-curve.
	off := append([]byte(nil), g...)
	off[len(off)-1] ^= 0x01
	if _, err := new(Point).SetBytes(off); err == nil {
		t.Fatal("off-curve point accepted")
	}

	// Wrong tag.
	badTag := append([]byte(nil), g...)
	badTag[0] = 0x05
	if _, err := new(Point).SetBytes(badTag); err == nil {
		t.Fatal("bad tag accepted")
	}

	// Compressed form not supported.
	if _, err := new(Point).SetBytes(append([]byte{0x02}, g[1:1+elementLen]...)); err == nil {
		t.Fatal("compressed point unexpectedly accepted")
	}

	// Wrong lengths.
	for _, n := range []int{0, 2, uncompressedLen - 1, uncompressedLen + 1} {
		if _, err := new(Point).SetBytes(make([]byte, n)); err == nil && n != 1 {
			t.Fatalf("SetBytes accepted %d-byte input", n)
		}
	}
}

func TestSelectConstantTimePick(t *testing.T) {
	g := mustGen(t)
	twoG := new(Point).Double(g)
	if got := new(Point).Select(g, twoG, 1); !bytes.Equal(affine(t, got), affine(t, g)) {
		t.Fatal("Select(cond=1) did not pick first")
	}
	if got := new(Point).Select(g, twoG, 0); !bytes.Equal(affine(t, got), affine(t, twoG)) {
		t.Fatal("Select(cond=0) did not pick second")
	}
}
