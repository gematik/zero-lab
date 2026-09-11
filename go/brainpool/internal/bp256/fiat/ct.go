package fiat

import (
	"encoding/binary"
	"math/bits"
)

// ConstantTimeLessOrEq returns 1 if x <= y and 0 otherwise, in constant time,
// where x and y are big-endian byte strings of equal length. It mirrors the
// standard library's internal subtle.ConstantTimeLessOrEqBytes, which is not
// exported.
func ConstantTimeLessOrEq(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}

	// Do a constant time subtraction chain y - x.
	// If there is no borrow at the end, then x <= y.
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

// invertEndianness swaps between the big-endian byte order used at the API and
// the little-endian order the generated code reads and writes.
func invertEndianness(v []byte) {
	for i := 0; i < len(v)/2; i++ {
		v[i], v[len(v)-1-i] = v[len(v)-1-i], v[i]
	}
}
