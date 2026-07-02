package bp256

import (
	"math/bits"

	"github.com/gematik/zero-lab/go/brainpool/internal/bp256/fiatn"
)

// scalarLen is the byte length of a brainpoolP256r1 scalar.
const scalarLen = 32

// n in 64-bit little-endian limbs (limb 0 is least significant). n is the group
// order 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7.
var nLimbs = [4]uint64{
	0x901E0E82974856A7,
	0x8C397AA3B561A6F7,
	0x3E660A909D838D71,
	0xA9FB57DBA1EEA9BC,
}

// reduceModN reduces a 32-byte big-endian value v modulo n in constant time and
// returns it as a scalar element. Because n > 2²⁵⁵, any 256-bit input is < 2n,
// so a single conditional subtraction of n suffices. Used for the ECDSA message
// representative z (the hash) and for r = R.x mod n.
func reduceModN(v []byte) *fiatn.Element {
	var b [scalarLen]byte
	copy(b[scalarLen-len(v):], v) // right-align (v is ≤ 32 bytes)

	// Parse into little-endian limbs.
	var x [4]uint64
	for i := 0; i < 4; i++ {
		x[i] = uint64(b[scalarLen-8*i-1]) |
			uint64(b[scalarLen-8*i-2])<<8 |
			uint64(b[scalarLen-8*i-3])<<16 |
			uint64(b[scalarLen-8*i-4])<<24 |
			uint64(b[scalarLen-8*i-5])<<32 |
			uint64(b[scalarLen-8*i-6])<<40 |
			uint64(b[scalarLen-8*i-7])<<48 |
			uint64(b[scalarLen-8*i-8])<<56
	}

	// d = x - n with borrow.
	var d [4]uint64
	var borrow uint64
	d[0], borrow = bits.Sub64(x[0], nLimbs[0], 0)
	d[1], borrow = bits.Sub64(x[1], nLimbs[1], borrow)
	d[2], borrow = bits.Sub64(x[2], nLimbs[2], borrow)
	d[3], borrow = bits.Sub64(x[3], nLimbs[3], borrow)

	// borrow == 1 means x < n: keep x. borrow == 0 means x ≥ n: use d.
	keepX := -borrow // all-ones if borrow==1, else 0
	var out [4]uint64
	for i := 0; i < 4; i++ {
		out[i] = (x[i] & keepX) | (d[i] &^ keepX)
	}

	// Serialise limbs back to big-endian and load (now guaranteed < n).
	var rb [scalarLen]byte
	for i := 0; i < 4; i++ {
		rb[scalarLen-8*i-1] = byte(out[i])
		rb[scalarLen-8*i-2] = byte(out[i] >> 8)
		rb[scalarLen-8*i-3] = byte(out[i] >> 16)
		rb[scalarLen-8*i-4] = byte(out[i] >> 24)
		rb[scalarLen-8*i-5] = byte(out[i] >> 32)
		rb[scalarLen-8*i-6] = byte(out[i] >> 40)
		rb[scalarLen-8*i-7] = byte(out[i] >> 48)
		rb[scalarLen-8*i-8] = byte(out[i] >> 56)
	}
	e, err := new(fiatn.Element).SetBytes(rb[:])
	if err != nil {
		// Unreachable: rb is < n by construction.
		panic("bp256: reduceModN produced a non-canonical scalar")
	}
	return e
}

// scalarFromCanonical loads a scalar that must already be in [0, n-1].
func scalarFromCanonical(v []byte) (*fiatn.Element, error) {
	var b [scalarLen]byte
	if len(v) > scalarLen {
		return new(fiatn.Element), errScalarRange
	}
	copy(b[scalarLen-len(v):], v)
	return new(fiatn.Element).SetBytes(b[:])
}
