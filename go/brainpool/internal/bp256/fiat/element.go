// Package fiat provides constant-time arithmetic in the two fields of
// brainpoolP256r1 (RFC 5639 §3.4): [Element] is an integer modulo the field
// prime p, [Scalar] an integer modulo the group order n. Both wrap generated,
// machine-checked code — p_fiat64.go and n_fiat64.go from Fiat Cryptography,
// p_invert.go and n_invert.go from addchain — behind the wrapper shape of the
// Go standard library's crypto/internal/fips140/nistec/fiat. Nothing outside
// the generated files touches a limb.
package fiat

import (
	"crypto/subtle"
	"errors"
)

// Element is an integer modulo
// p = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
// (the brainpoolP256r1 field prime, RFC 5639 §3.4).
//
// The zero value is a valid zero element.
type Element struct {
	// Values are represented internally always in the Montgomery domain, and
	// converted in Bytes and SetBytes.
	x bp256MontgomeryDomainFieldElement
}

const ElementLen = 32

type bp256UntypedFieldElement = [4]uint64

// One sets e = 1, and returns e.
func (e *Element) One() *Element {
	bp256SetOne(&e.x)
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
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [ElementLen]byte
	return e.bytes(&out)
}

func (e *Element) bytes(out *[ElementLen]byte) []byte {
	var tmp bp256NonMontgomeryDomainFieldElement
	bp256FromMontgomery(&tmp, &e.x)
	bp256ToBytes(out, (*bp256UntypedFieldElement)(&tmp))
	invertEndianness(out[:])
	return out[:]
}

// SetBytes sets e = v, where v is a big-endian 32-byte encoding, and returns e.
// If v is not 32 bytes or it encodes a value higher than p, SetBytes returns nil
// and an error, and e is unchanged.
func (e *Element) SetBytes(v []byte) (*Element, error) {
	if len(v) != ElementLen {
		return nil, errors.New("invalid Element encoding")
	}

	// Check for non-canonical encodings (p + k, 2p + k, etc.) by comparing to
	// the encoding of -1 mod p, so p - 1, the highest canonical encoding.
	var minusOneEncoding = new(Element).Sub(
		new(Element), new(Element).One()).Bytes()
	if ConstantTimeLessOrEq(v, minusOneEncoding) == 0 {
		return nil, errors.New("invalid Element encoding")
	}

	var in [ElementLen]byte
	copy(in[:], v)
	invertEndianness(in[:])
	var tmp bp256NonMontgomeryDomainFieldElement
	bp256FromBytes((*bp256UntypedFieldElement)(&tmp), &in)
	bp256ToMontgomery(&e.x, &tmp)
	return e, nil
}

// Add sets e = t1 + t2, and returns e.
func (e *Element) Add(t1, t2 *Element) *Element {
	bp256Add(&e.x, &t1.x, &t2.x)
	return e
}

// Sub sets e = t1 - t2, and returns e.
func (e *Element) Sub(t1, t2 *Element) *Element {
	bp256Sub(&e.x, &t1.x, &t2.x)
	return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *Element) Mul(t1, t2 *Element) *Element {
	bp256Mul(&e.x, &t1.x, &t2.x)
	return e
}

// Square sets e = t * t, and returns e.
func (e *Element) Square(t *Element) *Element {
	bp256Square(&e.x, &t.x)
	return e
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *Element) Select(a, b *Element, cond int) *Element {
	bp256Selectznz((*bp256UntypedFieldElement)(&v.x), bp256Uint1(cond),
		(*bp256UntypedFieldElement)(&b.x), (*bp256UntypedFieldElement)(&a.x))
	return v
}
