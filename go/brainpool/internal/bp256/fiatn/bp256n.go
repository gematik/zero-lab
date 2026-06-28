// Package fiatn provides constant-time arithmetic in the brainpoolP256r1 scalar
// field, i.e. integers modulo the group order
// n = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
// (RFC 5639 §3.4). It is the order-field counterpart of package fiat and is used
// for the ECDSA scalar arithmetic (k⁻¹, z + r·d) that must be constant time.
//
// Adapted from the Go standard library crypto/internal/fips140/nistec/fiat
// wrapper template; the arithmetic lives in the generated, machine-checked
// bp256n_fiat64.go and bp256n_invert.go.
package fiatn

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

// Element is an integer modulo the group order n.
//
// The zero value is a valid zero element.
type Element struct {
	x bp256nMontgomeryDomainFieldElement
}

const ElementLen = 32

type bp256nUntypedFieldElement = [4]uint64

// One sets e = 1, and returns e.
func (e *Element) One() *Element {
	bp256nSetOne(&e.x)
	return e
}

// Equal returns 1 if e == t, and zero otherwise.
func (e *Element) Equal(t *Element) int {
	eBytes := e.Bytes()
	tBytes := t.Bytes()
	return subtle.ConstantTimeCompare(eBytes, tBytes)
}

// IsZero returns 1 if e == 0, and zero otherwise.
func (e *Element) IsZero() int {
	zero := make([]byte, ElementLen)
	eBytes := e.Bytes()
	return subtle.ConstantTimeCompare(eBytes, zero)
}

// Set sets e = t, and returns e.
func (e *Element) Set(t *Element) *Element {
	e.x = t.x
	return e
}

// Bytes returns the 32-byte big-endian encoding of e.
func (e *Element) Bytes() []byte {
	var out [ElementLen]byte
	return e.bytes(&out)
}

func (e *Element) bytes(out *[ElementLen]byte) []byte {
	var tmp bp256nNonMontgomeryDomainFieldElement
	bp256nFromMontgomery(&tmp, &e.x)
	bp256nToBytes(out, (*bp256nUntypedFieldElement)(&tmp))
	bp256nInvertEndianness(out[:])
	return out[:]
}

// SetBytes sets e = v, where v is a big-endian 32-byte encoding of a value in
// [0, n-1], and returns e. If v is not 32 bytes or encodes a value ≥ n, it
// returns nil and an error, and e is unchanged.
func (e *Element) SetBytes(v []byte) (*Element, error) {
	if len(v) != ElementLen {
		return nil, errors.New("invalid scalar Element encoding")
	}
	var minusOneEncoding = new(Element).Sub(
		new(Element), new(Element).One()).Bytes()
	if ctLessOrEqBytes(v, minusOneEncoding) == 0 {
		return nil, errors.New("invalid scalar Element encoding")
	}
	var in [ElementLen]byte
	copy(in[:], v)
	bp256nInvertEndianness(in[:])
	var tmp bp256nNonMontgomeryDomainFieldElement
	bp256nFromBytes((*bp256nUntypedFieldElement)(&tmp), &in)
	bp256nToMontgomery(&e.x, &tmp)
	return e, nil
}

// Add sets e = t1 + t2, and returns e.
func (e *Element) Add(t1, t2 *Element) *Element {
	bp256nAdd(&e.x, &t1.x, &t2.x)
	return e
}

// Sub sets e = t1 - t2, and returns e.
func (e *Element) Sub(t1, t2 *Element) *Element {
	bp256nSub(&e.x, &t1.x, &t2.x)
	return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *Element) Mul(t1, t2 *Element) *Element {
	bp256nMul(&e.x, &t1.x, &t2.x)
	return e
}

// Square sets e = t * t, and returns e.
func (e *Element) Square(t *Element) *Element {
	bp256nSquare(&e.x, &t.x)
	return e
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *Element) Select(a, b *Element, cond int) *Element {
	bp256nSelectznz((*bp256nUntypedFieldElement)(&v.x), bp256nUint1(cond),
		(*bp256nUntypedFieldElement)(&b.x), (*bp256nUntypedFieldElement)(&a.x))
	return v
}

func bp256nInvertEndianness(v []byte) {
	for i := 0; i < len(v)/2; i++ {
		v[i], v[len(v)-1-i] = v[len(v)-1-i], v[i]
	}
}

func ctLessOrEqBytes(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}
	var b uint64
	for len(x) > 8 {
		x0 := binary.BigEndian.Uint64(x[len(x)-8:])
		y0 := binary.BigEndian.Uint64(y[len(y)-8:])
		_, b = bits.Sub64(y0, x0, b)
		x = x[:len(x)-8]
		y = y[:len(y)-8]
	}
	if len(x) > 0 {
		xb := make([]byte, 8)
		yb := make([]byte, 8)
		copy(xb[8-len(x):], x)
		copy(yb[8-len(y):], y)
		x0 := binary.BigEndian.Uint64(xb)
		y0 := binary.BigEndian.Uint64(yb)
		_, b = bits.Sub64(y0, x0, b)
	}
	return int(b ^ 1)
}
