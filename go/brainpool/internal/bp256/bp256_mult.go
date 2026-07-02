package bp256

// ScalarMult sets q = scalar·p and returns q, in constant time with respect to
// the value of scalar. scalar is a big-endian integer; every bit position is
// processed, so callers pass a fixed-width (32-byte) scalar to keep the running
// time independent of the secret's magnitude.
//
// The algorithm is the Montgomery ladder built on the complete (exception-free)
// addition formula, so it has no scalar-bit-dependent branches and no special
// cases — the property the legacy big.Int path lacks (see the package doc).
func (q *Point) ScalarMult(p *Point, scalar []byte) *Point {
	r0 := NewPoint()        // O
	r1 := new(Point).Set(p) // P
	tmp := &Point{}

	for _, b := range scalar {
		for bit := 7; bit >= 0; bit-- {
			swap := int(b>>uint(bit)) & 1
			cswap(r0, r1, swap, tmp)
			// r1 = r0 + r1; r0 = 2·r0 (Add tolerates aliasing).
			r1.Add(r0, r1)
			r0.Double(r0)
			cswap(r0, r1, swap, tmp)
		}
	}
	return q.Set(r0)
}

// ScalarBaseMult sets q = scalar·G and returns q.
func (q *Point) ScalarBaseMult(scalar []byte) *Point {
	return q.ScalarMult(new(Point).SetGenerator(), scalar)
}

// cswap conditionally swaps a and b in constant time when swap == 1, using tmp
// as scratch. The branch on swap is value-independent: Point.Select is
// constant-time, so the same field operations run regardless of swap.
func cswap(a, b *Point, swap int, tmp *Point) {
	tmp.Select(b, a, swap) // tmp = swap?b:a
	b.Select(a, b, swap)   // b   = swap?a:b
	a.Set(tmp)             // a   = tmp
}
