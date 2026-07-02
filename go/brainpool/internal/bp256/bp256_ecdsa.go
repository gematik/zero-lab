package bp256

import (
	"encoding/binary"
	"errors"
	"math/big"
	"math/bits"

	"github.com/gematik/zero-lab/go/brainpool/internal/bp256/fiatn"
)

var (
	errScalarRange = errors.New("bp256: scalar out of range [1, n-1]")
	errSignZero    = errors.New("bp256: signature r or s is zero; retry with a new nonce")
)

// nHalfBytes is ⌊n/2⌋ as a 32-byte big-endian value, the low-s threshold
// (SEC 1 §4.1.3, BIP-0062). n/2 is public, so computing it with big.Int is fine.
var nHalfBytes = func() []byte {
	n, _ := new(big.Int).SetString(hexN, 16)
	var b [scalarLen]byte
	new(big.Int).Rsh(n, 1).FillBytes(b[:])
	return b[:]
}()

// hashToScalar maps a prehash to the ECDSA message representative z = e mod n,
// where e is the leftmost N=256 bits of the hash (FIPS 186-5 §6.4.1 /
// BSI TR-03111 §5.2.1). For SHA-256 the hash is exactly 32 bytes.
func hashToScalar(hash []byte) *fiatn.Element {
	if len(hash) > scalarLen {
		hash = hash[:scalarLen]
	}
	return reduceModN(hash)
}

// SignWithNonce produces an ECDSA signature (r, s) over prehash using private
// scalar d and the supplied per-message nonce k (both 32-byte big-endian, in
// [1, n-1]). It performs the scalar arithmetic in constant time and normalises
// s to low-s. It returns errSignZero if r or s is zero (caller retries with a
// fresh nonce); callers using deterministic nonces effectively never hit this.
func SignWithNonce(d, k, prehash []byte) (r, s []byte, err error) {
	dE, err := scalarFromCanonical(d)
	if err != nil || dE.IsZero() == 1 {
		return nil, nil, errScalarRange
	}
	kE, err := scalarFromCanonical(k)
	if err != nil || kE.IsZero() == 1 {
		return nil, nil, errScalarRange
	}

	// R = k·G; r = R.x mod n.
	rPoint := new(Point).ScalarBaseMult(k)
	rx, err := rPoint.BytesX()
	if err != nil {
		return nil, nil, err
	}
	rE := reduceModN(rx)
	if rE.IsZero() == 1 {
		return nil, nil, errSignZero
	}

	z := hashToScalar(prehash)

	// s = k⁻¹·(z + r·d) mod n.
	rd := new(fiatn.Element).Mul(rE, dE)
	sum := new(fiatn.Element).Add(z, rd)
	kInv := new(fiatn.Element).Invert(kE)
	sE := new(fiatn.Element).Mul(kInv, sum)
	if sE.IsZero() == 1 {
		return nil, nil, errSignZero
	}

	normalizeLowS(sE)
	return rE.Bytes(), sE.Bytes(), nil
}

// normalizeLowS sets s = n − s when s > n/2, so signatures are non-malleable
// (SEC 1 §4.1.3). The compare is constant time; the conditional negation is
// computed unconditionally and selected.
func normalizeLowS(s *fiatn.Element) {
	high := 1 ^ ctLessOrEqBytesScalar(s.Bytes(), nHalfBytes) // 1 if s > n/2
	neg := new(fiatn.Element).Sub(new(fiatn.Element), s)     // n - s
	s.Select(neg, s, high)
}

// Signature verification is intentionally not implemented here: it operates only
// on public data, so it has no constant-time requirement and is performed with
// the standard library's crypto/ecdsa.Verify over the brainpool curve (see the
// parent package's bridge and josebp/verify.go). This keeps the hand-written,
// security-sensitive code limited to the secret-scalar operations (signing and
// ECDH) that genuinely need a constant-time implementation.

// ctLessOrEqBytesScalar returns 1 if x ≤ y (both equal-length big-endian byte
// strings) in constant time, via a subtraction chain y - x from the least
// significant word: no final borrow means x ≤ y.
func ctLessOrEqBytesScalar(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}
	var b uint64
	for len(x) >= 8 {
		x0 := binary.BigEndian.Uint64(x[len(x)-8:])
		y0 := binary.BigEndian.Uint64(y[len(y)-8:])
		_, b = bits.Sub64(y0, x0, b)
		x = x[:len(x)-8]
		y = y[:len(y)-8]
	}
	return int(b ^ 1)
}
