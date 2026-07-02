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

// SignP256r1 signs prehash with priv using the constant-time core: an RFC 6979
// deterministic nonce and low-s normalisation. It returns the fixed-width r‖s
// encoding (RFC 7518 §3.4). priv must be a brainpoolP256r1 key.
func SignP256r1(priv *ecdsa.PrivateKey, prehash []byte) ([]byte, error) {
	if !isP256r1(priv.Curve) {
		return nil, errors.New("brainpool: SignP256r1 requires a brainpoolP256r1 key")
	}
	r, s, err := bp256.SignDeterministic(scalarBytes(priv.D), prehash)
	if err != nil {
		return nil, err
	}
	return append(padBytes(r, 32), padBytes(s, 32)...), nil
}

// SignP256r1Random is the opt-out variant of SignP256r1 that draws a random
// per-message nonce from rng instead of RFC 6979. It still uses the constant-time
// core and low-s normalisation. Prefer SignP256r1 unless a random nonce is
// specifically required.
func SignP256r1Random(rng io.Reader, priv *ecdsa.PrivateKey, prehash []byte) ([]byte, error) {
	if !isP256r1(priv.Curve) {
		return nil, errors.New("brainpool: SignP256r1Random requires a brainpoolP256r1 key")
	}
	k, err := randomScalar(rng, priv.Curve.Params().N)
	if err != nil {
		return nil, err
	}
	r, s, err := bp256.SignWithNonce(scalarBytes(priv.D), k, prehash)
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

// randomScalar returns a uniformly random 32-byte scalar in [1, n-1].
func randomScalar(rng io.Reader, n *big.Int) ([]byte, error) {
	if rng == nil {
		rng = rand.Reader
	}
	for {
		k, err := rand.Int(rng, n)
		if err != nil {
			return nil, err
		}
		if k.Sign() != 0 {
			return scalarBytes(k), nil
		}
	}
}
