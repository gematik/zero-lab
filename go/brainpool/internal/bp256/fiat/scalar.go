package fiat

import (
	"crypto/subtle"
	"errors"
)

// Scalar is an integer modulo the group order
// n = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7,
// the field of ECDSA's k⁻¹ and z + r·d.
//
// The zero value is a valid zero scalar.
type Scalar struct {
	x bp256nMontgomeryDomainFieldElement
}

const ScalarLen = 32

type bp256nUntypedFieldElement = [4]uint64

// One sets e = 1, and returns e.
func (e *Scalar) One() *Scalar {
	bp256nSetOne(&e.x)
	return e
}

// Equal returns 1 if e == t, and zero otherwise.
func (e *Scalar) Equal(t *Scalar) int {
	eBytes := e.Bytes()
	tBytes := t.Bytes()
	return subtle.ConstantTimeCompare(eBytes, tBytes)
}

// IsZero returns 1 if e == 0, and zero otherwise.
func (e *Scalar) IsZero() int {
	zero := make([]byte, ScalarLen)
	eBytes := e.Bytes()
	return subtle.ConstantTimeCompare(eBytes, zero)
}

// Set sets e = t, and returns e.
func (e *Scalar) Set(t *Scalar) *Scalar {
	e.x = t.x
	return e
}

// Bytes returns the 32-byte big-endian encoding of e.
func (e *Scalar) Bytes() []byte {
	var out [ScalarLen]byte
	return e.bytes(&out)
}

func (e *Scalar) bytes(out *[ScalarLen]byte) []byte {
	var tmp bp256nNonMontgomeryDomainFieldElement
	bp256nFromMontgomery(&tmp, &e.x)
	bp256nToBytes(out, (*bp256nUntypedFieldElement)(&tmp))
	invertEndianness(out[:])
	return out[:]
}

// SetBytes sets e = v, where v is a big-endian 32-byte encoding of a value in
// [0, n-1], and returns e. If v is not 32 bytes or encodes a value ≥ n, it
// returns nil and an error, and e is unchanged.
func (e *Scalar) SetBytes(v []byte) (*Scalar, error) {
	if len(v) != ScalarLen {
		return nil, errors.New("invalid scalar Scalar encoding")
	}
	var minusOneEncoding = new(Scalar).Sub(
		new(Scalar), new(Scalar).One()).Bytes()
	if ConstantTimeLessOrEq(v, minusOneEncoding) == 0 {
		return nil, errors.New("invalid scalar Scalar encoding")
	}
	var in [ScalarLen]byte
	copy(in[:], v)
	invertEndianness(in[:])
	var tmp bp256nNonMontgomeryDomainFieldElement
	bp256nFromBytes((*bp256nUntypedFieldElement)(&tmp), &in)
	bp256nToMontgomery(&e.x, &tmp)
	return e, nil
}

// Add sets e = t1 + t2, and returns e.
func (e *Scalar) Add(t1, t2 *Scalar) *Scalar {
	bp256nAdd(&e.x, &t1.x, &t2.x)
	return e
}

// Sub sets e = t1 - t2, and returns e.
func (e *Scalar) Sub(t1, t2 *Scalar) *Scalar {
	bp256nSub(&e.x, &t1.x, &t2.x)
	return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *Scalar) Mul(t1, t2 *Scalar) *Scalar {
	bp256nMul(&e.x, &t1.x, &t2.x)
	return e
}

// Square sets e = t * t, and returns e.
func (e *Scalar) Square(t *Scalar) *Scalar {
	bp256nSquare(&e.x, &t.x)
	return e
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *Scalar) Select(a, b *Scalar, cond int) *Scalar {
	bp256nSelectznz((*bp256nUntypedFieldElement)(&v.x), bp256nUint1(cond),
		(*bp256nUntypedFieldElement)(&b.x), (*bp256nUntypedFieldElement)(&a.x))
	return v
}
