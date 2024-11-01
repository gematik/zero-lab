package brainpool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"hash"
	"io"
)

func DeriveECDHES(alg string, apuData, apvData []byte, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, size int) []byte {
	if size > 1<<16 {
		panic("ECDH-ES output size too large, must be less than or equal to 64 KiB")
	}

	// Prefix inputs with length
	algID := lengthPrefixed([]byte(alg))
	ptyUInfo := lengthPrefixed(apuData)
	ptyVInfo := lengthPrefixed(apvData)

	// Encode output size in bits for suppPubInfo
	supPubInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(supPubInfo, uint32(size)*8)

	// Validate that the public key is on the same curve as the private key
	if !priv.Curve.IsOnCurve(pub.X, pub.Y) {
		panic("public key not on the same curve as private key")
	}

	// Calculate shared secret Z
	zX, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	zBytes := zX.Bytes()

	// Ensure zBytes is padded to the correct size for the curve
	octSize := curveCoordinateSize(priv.Curve)
	if len(zBytes) < octSize {
		paddedZ := make([]byte, octSize)
		copy(paddedZ[octSize-len(zBytes):], zBytes)
		zBytes = paddedZ
	}

	// Create a KDF reader with SHA-256
	reader := newKDF(crypto.SHA256, zBytes, algID, ptyUInfo, ptyVInfo, supPubInfo, nil)
	key := make([]byte, size)

	// Read from the KDF into the key slice
	_, _ = reader.Read(key)

	return key
}

// curveCoordinateSize returns the size in octets for a coordinate on an elliptic curve.
func curveCoordinateSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8 // Equivalent to bitLen / 8 rounded up
}

// lengthPrefixed returns a byte slice prefixed with its length in 32-bit big-endian format.
func lengthPrefixed(data []byte) []byte {
	out := make([]byte, len(data)+4)
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)
	return out
}

type kdf struct {
	z, info []byte
	i       uint32
	cache   []byte
	hasher  hash.Hash
}

// newKDF builds a KDF reader based on the given inputs.
func newKDF(hash crypto.Hash, z, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo []byte) io.Reader {
	info := append(append(append(append(append([]byte{}, algID...), ptyUInfo...), ptyVInfo...), supPubInfo...), supPrivInfo...)
	return &kdf{
		z:      z,
		info:   info,
		hasher: hash.New(),
		cache:  nil,
		i:      1,
	}
}

func (ctx *kdf) Read(out []byte) (int, error) {
	totalCopied := 0

	// Use cached data if available
	if len(ctx.cache) > 0 {
		n := copy(out, ctx.cache)
		totalCopied += n
		ctx.cache = ctx.cache[n:]
		if totalCopied == len(out) {
			return totalCopied, nil
		}
	}

	// Generate new hash blocks until the output buffer is filled
	for totalCopied < len(out) {
		ctx.hasher.Reset()

		// Write counter in big-endian format to the hasher
		counter := [4]byte{}
		binary.BigEndian.PutUint32(counter[:], ctx.i)
		_, _ = ctx.hasher.Write(counter[:])

		// Write shared secret Z and info
		_, _ = ctx.hasher.Write(ctx.z)
		_, _ = ctx.hasher.Write(ctx.info)

		// Get the hash sum and copy to the output buffer
		hash := ctx.hasher.Sum(nil)
		n := copy(out[totalCopied:], hash)
		totalCopied += n

		// Save any unused portion of the hash to the cache
		if n < len(hash) {
			ctx.cache = hash[n:]
		} else {
			ctx.cache = nil
		}

		ctx.i++
	}

	return totalCopied, nil
}
