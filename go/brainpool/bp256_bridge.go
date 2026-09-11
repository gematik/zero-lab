package brainpool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/gematik/zero-lab/go/brainpool/internal/bp256"
)

// isP256r1 reports whether c is the brainpoolP256r1 curve, the curve whose
// secret-scalar operations are routed through the constant-time core.
func isP256r1(c elliptic.Curve) bool {
	return c != nil && c.Params().Name == "brainpoolP256r1"
}

// scalarBytes returns the private scalar as a fixed-width 32-byte big-endian
// value, so the constant-time path never sees a variable-length input.
func scalarBytes(d *big.Int) []byte {
	b := make([]byte, 32)
	d.FillBytes(b)
	return b
}

// signP256r1 signs prehash with priv using the constant-time core: an RFC 6979
// deterministic nonce and low-s normalisation. It returns the fixed-width r‖s
// encoding (RFC 7518 §3.4). priv must be a brainpoolP256r1 key.
func signP256r1(priv *ecdsa.PrivateKey, prehash []byte) ([]byte, error) {
	if !isP256r1(priv.Curve) {
		return nil, errors.New("brainpool: signP256r1 requires a brainpoolP256r1 key")
	}
	r, s, err := bp256.SignDeterministic(scalarBytes(priv.D), prehash)
	if err != nil {
		return nil, err
	}
	return append(padBytes(r, 32), padBytes(s, 32)...), nil
}

// ECDHP256r1 computes the brainpoolP256r1 ECDH shared secret (the x-coordinate
// of priv·peer, BSI TR-03111 §3.5.1) using the constant-time core. The peer
// point (pubX, pubY) is validated (on-curve, in range) before use.
func ECDHP256r1(priv *ecdsa.PrivateKey, pubX, pubY *big.Int) ([]byte, error) {
	if !isP256r1(priv.Curve) {
		return nil, errors.New("brainpool: ECDHP256r1 requires a brainpoolP256r1 key")
	}
	enc := make([]byte, 1+2*32)
	enc[0] = 0x04
	pubX.FillBytes(enc[1:33])
	pubY.FillBytes(enc[33:])
	peer, err := new(bp256.Point).SetBytes(enc)
	if err != nil {
		return nil, err
	}
	return bp256.ECDH(scalarBytes(priv.D), peer)
}

// derivePublicKey returns d·G. For brainpoolP256r1 the multiplication runs in
// the constant-time core; the other curves use the generic big.Int path, which
// is acceptable there because they are not software-signing curves.
func derivePublicKey(curve elliptic.Curve, d *big.Int) (x, y *big.Int, err error) {
	if !isP256r1(curve) {
		x, y = curve.ScalarBaseMult(d.Bytes())
		return x, y, nil
	}
	enc, err := bp256.PublicKey(scalarBytes(d))
	if err != nil {
		return nil, nil, err
	}
	return new(big.Int).SetBytes(enc[1:33]), new(big.Int).SetBytes(enc[33:]), nil
}

// GenerateKey returns a fresh private key on curve. Brainpool keys derive
// their public point through derivePublicKey, so a brainpoolP256r1 key never
// has its secret multiplied by variable-time code; any other curve is handed
// to the standard library. A nil rng means crypto/rand.
func GenerateKey(curve elliptic.Curve, rng io.Reader) (*ecdsa.PrivateKey, error) {
	if !isBrainpoolCurve(curve) {
		return ecdsa.GenerateKey(curve, rng)
	}
	if rng == nil {
		rng = rand.Reader
	}
	d, err := rand.Int(rng, new(big.Int).Sub(curve.Params().N, big.NewInt(1)))
	if err != nil {
		return nil, err
	}
	d.Add(d, big.NewInt(1)) // uniform in [1, n-1]
	x, y, err := derivePublicKey(curve, d)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}
