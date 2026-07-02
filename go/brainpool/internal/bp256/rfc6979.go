package bp256

import (
	"crypto/hmac"
	"crypto/sha256"
)

// rfc6979Nonce derives a deterministic ECDSA nonce k ∈ [1, n-1] from the private
// scalar d (32-byte big-endian) and the message prehash, per RFC 6979 §3.2 using
// HMAC-SHA256. Deterministic nonces remove the catastrophic "predictable or
// repeated RNG → private-key recovery" failure mode (the curve order is 256 bits
// and SHA-256 is the bound hash, so qlen = hlen = 256).
func rfc6979Nonce(d, prehash []byte) []byte {
	const holen = sha256.Size // 32

	// x = int2octets(d); h1 = bits2octets(prehash) = (prehash mod n) as octets.
	x := make([]byte, scalarLen)
	copy(x[scalarLen-len(d):], d)
	h1 := bits2octets(prehash)

	// Step b–c: V = 0x01..., K = 0x00...
	v := bytesRepeat(0x01, holen)
	k := bytesRepeat(0x00, holen)

	// Step d: K = HMAC_K(V || 0x00 || x || h1)
	k = mac(k, concat(v, []byte{0x00}, x, h1))
	// Step e: V = HMAC_K(V)
	v = mac(k, v)
	// Step f: K = HMAC_K(V || 0x01 || x || h1)
	k = mac(k, concat(v, []byte{0x01}, x, h1))
	// Step g: V = HMAC_K(V)
	v = mac(k, v)

	// Step h: generate candidates until one is a valid scalar.
	for {
		// T is one HMAC output (holen == qlen/8 == 32), so bits2int(T) = T.
		v = mac(k, v)
		t := v

		if scalar, err := scalarFromCanonical(t); err == nil && scalar.IsZero() == 0 {
			out := make([]byte, scalarLen)
			copy(out, t)
			return out
		}

		// Candidate rejected (k = 0 or k ≥ n): K = HMAC_K(V || 0x00); V = HMAC_K(V).
		k = mac(k, append(append([]byte{}, v...), 0x00))
		v = mac(k, v)
	}
}

// bits2octets implements RFC 6979 §2.3.4: reduce the prehash (taken as
// bits2int) modulo n and return the 32-octet big-endian encoding.
func bits2octets(prehash []byte) []byte {
	if len(prehash) > scalarLen {
		prehash = prehash[:scalarLen]
	}
	return reduceModN(prehash).Bytes()
}

func mac(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// SignDeterministic signs prehash with private scalar d using an RFC 6979
// deterministic nonce, and applies low-s normalisation. This is the default
// software-signing path: no RNG is consumed, so a weak or broken RNG cannot
// leak the key.
func SignDeterministic(d, prehash []byte) (r, s []byte, err error) {
	k := rfc6979Nonce(d, prehash)
	return SignWithNonce(d, k, prehash)
}
