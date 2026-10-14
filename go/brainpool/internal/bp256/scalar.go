// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package bp256

import (
	"crypto/subtle"
	"encoding/binary"
	"math/bits"

	"github.com/gematik/zero-lab/go/brainpool/internal/bp256/fiat"
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
