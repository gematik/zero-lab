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

// SignFunc signs a digest and returns the raw fixed-width r‖s ECDSA signature
// (RFC 7518 §3.4). It abstracts over software keys and hardware tokens
// (smartcards via the gematik connector), where the private key is not
// extractable. The JOSE layer lives in brainpool/josebp.
type SignFunc func(hash []byte) ([]byte, error)

// SignFuncPrivateKey returns a SignFunc backed by a software ECDSA private
// key. For brainpoolP256r1 it signs in the constant-time core with an RFC
// 6979 deterministic nonce and low-s normalisation; every other curve signs
// with the standard library, which for the remaining Brainpool curves is the
// generic variable-time path — acceptable because the TI does not issue
// software-held keys on them.
func SignFuncPrivateKey(key *ecdsa.PrivateKey) SignFunc {
	return func(hash []byte) ([]byte, error) {
		size := (key.Curve.Params().BitSize + 7) / 8
		if hasConstantTimeCore(key.Curve) {
			r, s, err := bp256.Sign(scalarBytes(key.D, size), hash)
			if err != nil {
				return nil, err
			}
			return append(padBytes(r, size), padBytes(s, size)...), nil
		}
		r, s, err := ecdsa.Sign(rand.Reader, key, hash)
		if err != nil {
			return nil, err
		}
		return append(padBytes(r.Bytes(), size), padBytes(s.Bytes(), size)...), nil
	}
}

// ECDH returns the shared secret of priv and pub: the x-coordinate of
// priv·pub as a fixed-width big-endian value (BSI TR-03111 §3.5.1), which is
// the Z input of the JOSE Concat KDF. pub is validated before any arithmetic.
// brainpoolP256r1 runs in the constant-time core; other curves on the
// generic path.
func ECDH(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	if priv == nil || priv.Curve == nil || priv.D == nil {
		return nil, errors.New("brainpool: nil private key")
	}
	if err := ValidatePublicKey(pub); err != nil {
		return nil, err
	}
	if pub.Curve.Params().Name != priv.Curve.Params().Name {
		return nil, errors.New("brainpool: ECDH keys are on different curves")
	}
	size := (priv.Curve.Params().BitSize + 7) / 8
	if hasConstantTimeCore(priv.Curve) {
		return bp256.ECDH(scalarBytes(priv.D, size), encodePoint(pub, size))
	}
	x, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return padBytes(x.Bytes(), size), nil
}

// GenerateKey returns a fresh private key on curve. Brainpool keys derive
// their public point through derivePublicKey, so a brainpoolP256r1 secret is
// never multiplied by variable-time code; any other curve is handed to the
// standard library. A nil rng means crypto/rand.
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

// derivePublicKey returns d·G, in the constant-time core where there is one.
func derivePublicKey(curve elliptic.Curve, d *big.Int) (x, y *big.Int, err error) {
	if !hasConstantTimeCore(curve) {
		x, y = curve.ScalarBaseMult(d.Bytes())
		return x, y, nil
	}
	size := (curve.Params().BitSize + 7) / 8
	enc, err := bp256.PublicKey(scalarBytes(d, size))
	if err != nil {
		return nil, nil, err
	}
	return new(big.Int).SetBytes(enc[1 : 1+size]), new(big.Int).SetBytes(enc[1+size:]), nil
}

// scalarBytes returns d as a fixed-width big-endian value, so the constant-time
// core never sees a length that depends on the secret's magnitude.
func scalarBytes(d *big.Int, size int) []byte {
	b := make([]byte, size)
	d.FillBytes(b)
	return b
}

// encodePoint returns the SEC 1 uncompressed encoding 0x04‖X‖Y.
func encodePoint(pub *ecdsa.PublicKey, size int) []byte {
	b := make([]byte, 1+2*size)
	b[0] = 4
	pub.X.FillBytes(b[1 : 1+size])
	pub.Y.FillBytes(b[1+size:])
	return b
}

func padBytes(v []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(v):], v)
	return out
}
