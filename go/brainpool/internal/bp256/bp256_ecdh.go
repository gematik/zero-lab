package bp256

import "errors"

// ECDH computes the brainpoolP256r1 ECDH shared secret per BSI TR-03111 §3.5.1:
// the x-coordinate of d·peer, returned as a 32-byte big-endian value. d is the
// private scalar (32-byte big-endian, in [1, n-1]); peer is the validated peer
// public point. It returns an error if the result is the point at infinity (the
// caller must reject and retry per the spec).
func ECDH(d []byte, peer *Point) ([]byte, error) {
	if peer.IsInfinity() == 1 {
		return nil, errors.New("bp256: ECDH peer is the point at infinity")
	}
	shared := new(Point).ScalarMult(peer, d)
	if shared.IsInfinity() == 1 {
		return nil, errors.New("bp256: ECDH produced the point at infinity")
	}
	return shared.BytesX()
}
