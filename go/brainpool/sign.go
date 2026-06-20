package brainpool

import (
	"crypto/ecdsa"
	"crypto/rand"
)

// SignFunc signs a digest and returns the raw fixed-width r‖s ECDSA signature (RFC 7518 §3.4). It
// abstracts over software keys and hardware tokens (smartcards via the gematik connector), where
// the private key is not extractable. The JOSE layer lives in brainpool/josebp.
type SignFunc func(hash []byte) ([]byte, error)

// SignFuncPrivateKey returns a SignFunc backed by a software ECDSA private key.
func SignFuncPrivateKey(sigPrK *ecdsa.PrivateKey) SignFunc {
	return func(hash []byte) ([]byte, error) {
		r, s, err := ecdsa.Sign(rand.Reader, sigPrK, hash)
		if err != nil {
			return nil, err
		}

		keyBytes := sigPrK.Curve.Params().BitSize / 8
		rBytesPadded := padBytes(r.Bytes(), keyBytes)
		sBytesPadded := padBytes(s.Bytes(), keyBytes)

		return append(rBytesPadded, sBytesPadded...), nil
	}
}

func padBytes(input []byte, length int) []byte {
	padded := make([]byte, length)
	copy(padded[length-len(input):], input)
	return padded
}
