package bp256

import (
	"crypto/subtle"
	"encoding/binary"
	"github.com/gematik/zero-lab/go/brainpool/internal/bp256/fiat"
	"math/bits"
)

// scalarLen is the byte length of a brainpoolP256r1 scalar.
const scalarLen = 32

// nBytes is the group order n as a 32-byte big-endian value.
var nBytes = func() (b [scalarLen]byte) {
	copy(b[:], hexToFixed(hexN))
	return b
}()

// reduceModN reduces a big-endian value of at most 32 bytes modulo n in
// constant time. n > 2²⁵⁵, so any 256-bit input is below 2n and one
// conditional subtraction suffices. Used for the ECDSA message representative
// z (the hash) and for r = R.x mod n.
func reduceModN(v []byte) *fiat.Scalar {
	var x [scalarLen]byte
	copy(x[scalarLen-len(v):], v)
	d, borrow := subBytes(x, nBytes)
	// borrow == 1 means x < n: keep x; otherwise x − n is the residue.
	subtle.ConstantTimeCopy(int(borrow^1), x[:], d[:])
	e, err := new(fiat.Scalar).SetBytes(x[:])
	if err != nil {
		// Unreachable: x is < n by construction.
		panic("bp256: reduceModN produced a non-canonical scalar")
	}
	return e
}

// subBytes returns a − b for equal-width big-endian values, with the final
// borrow (1 if a < b).
func subBytes(a, b [scalarLen]byte) (out [scalarLen]byte, borrow uint64) {
	for i := scalarLen; i > 0; i -= 8 {
		var w uint64
		w, borrow = bits.Sub64(binary.BigEndian.Uint64(a[i-8:i]), binary.BigEndian.Uint64(b[i-8:i]), borrow)
		binary.BigEndian.PutUint64(out[i-8:i], w)
	}
	return out, borrow
}

// scalarFromCanonical loads a scalar that must already be in [0, n-1].
func scalarFromCanonical(v []byte) (*fiat.Scalar, error) {
	var b [scalarLen]byte
	if len(v) > scalarLen {
		return new(fiat.Scalar), errScalarRange
	}
	copy(b[scalarLen-len(v):], v)
	return new(fiat.Scalar).SetBytes(b[:])
}
