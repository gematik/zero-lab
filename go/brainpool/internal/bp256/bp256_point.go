package bp256

import (
	"errors"

	"github.com/gematik/zero-lab/go/brainpool/internal/bp256/fiat"
)

// Point is a brainpoolP256r1 point in homogeneous projective coordinates
// (X:Y:Z), where the affine point is (X/Z, Y/Z) and the point at infinity is
// (0:1:0). The zero value is NOT valid; use NewPoint.
type Point struct {
	x, y, z fiat.Element
}

const (
	elementLen      = fiat.ElementLen
	uncompressedLen = 1 + 2*elementLen
	infinityEncoded = 0
	uncompressedTag = 4
)

// NewPoint returns a new Point set to the point at infinity (0:1:0).
func NewPoint() *Point {
	p := &Point{}
	p.y.One()
	return p
}

// SetGenerator sets p to the curve generator G and returns p.
func (p *Point) SetGenerator() *Point {
	g := generatorBytes()
	// g is the trusted, on-curve generator constant; SetBytes validates it.
	if _, err := p.SetBytes(g); err != nil {
		panic("bp256: invalid generator constant: " + err.Error())
	}
	return p
}

// Set sets p = q and returns p.
func (p *Point) Set(q *Point) *Point {
	p.x.Set(&q.x)
	p.y.Set(&q.y)
	p.z.Set(&q.z)
	return p
}

// SetBytes sets p to the uncompressed or infinity point encoded in b, per SEC 1
// v2.0 §2.3.4, validating that the point is on the curve. Compressed encodings
// are not accepted (gematik uses uncompressed points exclusively). On error the
// receiver is unchanged.
func (p *Point) SetBytes(b []byte) (*Point, error) {
	switch {
	case len(b) == 1 && b[0] == infinityEncoded:
		return p.Set(NewPoint()), nil

	case len(b) == uncompressedLen && b[0] == uncompressedTag:
		x, err := new(fiat.Element).SetBytes(b[1 : 1+elementLen])
		if err != nil {
			return nil, err
		}
		y, err := new(fiat.Element).SetBytes(b[1+elementLen:])
		if err != nil {
			return nil, err
		}
		if err := checkOnCurve(x, y); err != nil {
			return nil, err
		}
		p.x.Set(x)
		p.y.Set(y)
		p.z.One()
		return p, nil

	default:
		return nil, errors.New("bp256: invalid point encoding")
	}
}

// polynomial sets y2 = x³ + a·x + b and returns y2.
func polynomial(y2, x *fiat.Element) *fiat.Element {
	a, b, _ := curveConsts()
	y2.Square(x)  // x²
	y2.Mul(y2, x) // x³
	ax := new(fiat.Element).Mul(a, x)
	y2.Add(y2, ax) // x³ + a·x
	return y2.Add(y2, b)
}

func checkOnCurve(x, y *fiat.Element) error {
	rhs := polynomial(new(fiat.Element), x)
	lhs := new(fiat.Element).Square(y)
	if rhs.Equal(lhs) != 1 {
		return errors.New("bp256: point not on curve")
	}
	return nil
}

// Bytes returns the SEC 1 uncompressed encoding of p, or the single-byte
// infinity encoding.
func (p *Point) Bytes() []byte {
	var out [uncompressedLen]byte
	return p.bytes(&out)
}

func (p *Point) bytes(out *[uncompressedLen]byte) []byte {
	if p.z.IsZero() == 1 {
		return append(out[:0], 0)
	}
	zinv := new(fiat.Element).Invert(&p.z)
	x := new(fiat.Element).Mul(&p.x, zinv)
	y := new(fiat.Element).Mul(&p.y, zinv)
	buf := append(out[:0], uncompressedTag)
	buf = append(buf, x.Bytes()...)
	buf = append(buf, y.Bytes()...)
	return buf
}

// BytesX returns the big-endian encoding of the affine x-coordinate of p, or an
// error if p is the point at infinity. Used for ECDH (BSI TR-03111 §3.5.1).
func (p *Point) BytesX() ([]byte, error) {
	if p.z.IsZero() == 1 {
		return nil, errors.New("bp256: point is the point at infinity")
	}
	zinv := new(fiat.Element).Invert(&p.z)
	x := new(fiat.Element).Mul(&p.x, zinv)
	return x.Bytes(), nil
}

// IsInfinity returns 1 if p is the point at infinity, 0 otherwise.
func (p *Point) IsInfinity() int {
	return p.z.IsZero()
}

// Select sets p to a if cond == 1, and to b if cond == 0, in constant time, and
// returns p.
func (p *Point) Select(a, b *Point, cond int) *Point {
	p.x.Select(&a.x, &b.x, cond)
	p.y.Select(&a.y, &b.y, cond)
	p.z.Select(&a.z, &b.z, cond)
	return p
}

// Negate sets p = -q and returns p. The negation of (X:Y:Z) is (X:-Y:Z).
func (p *Point) Negate(q *Point) *Point {
	p.x.Set(&q.x)
	p.y.Sub(new(fiat.Element), &q.y)
	p.z.Set(&q.z)
	return p
}

// Add sets q = p1 + p2 and returns q. The points may overlap. It uses the
// complete (exception-free) addition formula for general short-Weierstrass
// curves: Renes–Costello–Batina, "Complete addition formulas for prime order
// elliptic curves" (https://eprint.iacr.org/2015/1060), Algorithm 1. Constants
// a and b3 = 3b are the curve parameters. brainpoolP256r1 has a ≠ −3, so the
// general Algorithm 1 is required rather than the a = −3 specialisation.
func (q *Point) Add(p1, p2 *Point) *Point {
	a, _, b3 := curveConsts()

	t0 := new(fiat.Element).Mul(&p1.x, &p2.x) // t0 = X1*X2
	t1 := new(fiat.Element).Mul(&p1.y, &p2.y) // t1 = Y1*Y2
	t2 := new(fiat.Element).Mul(&p1.z, &p2.z) // t2 = Z1*Z2
	t3 := new(fiat.Element).Add(&p1.x, &p1.y) // t3 = X1+Y1
	t4 := new(fiat.Element).Add(&p2.x, &p2.y) // t4 = X2+Y2
	t3.Mul(t3, t4)                            // t3 = t3*t4
	t4.Add(t0, t1)                            // t4 = t0+t1
	t3.Sub(t3, t4)                            // t3 = t3-t4
	t4.Add(&p1.x, &p1.z)                      // t4 = X1+Z1
	t5 := new(fiat.Element).Add(&p2.x, &p2.z) // t5 = X2+Z2
	t4.Mul(t4, t5)                            // t4 = t4*t5
	t5.Add(t0, t2)                            // t5 = t0+t2
	t4.Sub(t4, t5)                            // t4 = t4-t5
	t5.Add(&p1.y, &p1.z)                      // t5 = Y1+Z1
	x3 := new(fiat.Element).Add(&p2.y, &p2.z) // X3 = Y2+Z2
	t5.Mul(t5, x3)                            // t5 = t5*X3
	x3.Add(t1, t2)                            // X3 = t1+t2
	t5.Sub(t5, x3)                            // t5 = t5-X3
	z3 := new(fiat.Element).Mul(a, t4)        // Z3 = a*t4
	x3.Mul(b3, t2)                            // X3 = b3*t2
	z3.Add(x3, z3)                            // Z3 = X3+Z3
	x3.Sub(t1, z3)                            // X3 = t1-Z3
	z3.Add(t1, z3)                            // Z3 = t1+Z3
	y3 := new(fiat.Element).Mul(x3, z3)       // Y3 = X3*Z3
	t1.Add(t0, t0)                            // t1 = t0+t0
	t1.Add(t1, t0)                            // t1 = t1+t0
	t2.Mul(a, t2)                             // t2 = a*t2
	t4.Mul(b3, t4)                            // t4 = b3*t4
	t1.Add(t1, t2)                            // t1 = t1+t2
	t2.Sub(t0, t2)                            // t2 = t0-t2
	t2.Mul(a, t2)                             // t2 = a*t2
	t4.Add(t4, t2)                            // t4 = t4+t2
	t0.Mul(t1, t4)                            // t0 = t1*t4
	y3.Add(y3, t0)                            // Y3 = Y3+t0
	t0.Mul(t5, t4)                            // t0 = t5*t4
	x3.Mul(t3, x3)                            // X3 = t3*X3
	x3.Sub(x3, t0)                            // X3 = X3-t0
	t0.Mul(t3, t1)                            // t0 = t3*t1
	z3.Mul(t5, z3)                            // Z3 = t5*Z3
	z3.Add(z3, t0)                            // Z3 = Z3+t0

	q.x.Set(x3)
	q.y.Set(y3)
	q.z.Set(z3)
	return q
}

// Double sets q = p + p and returns q. Because Add is complete (handles the
// doubling case correctly), doubling is a special case of addition; using it
// here avoids carrying a second hand-transcribed formula.
func (q *Point) Double(p *Point) *Point {
	return q.Add(p, p)
}
