package brainpool

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

func DeriveECDHES(algorithm string, apuData, apvData []byte, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, keySize int) ([]byte, error) {
	if keySize > 1<<16 {
		return nil, errors.New("key size too large: must be less than or equal to 64 KiB")
	}

	// Prefix inputs with length
	algorithmID := lengthPrefixed([]byte(algorithm))
	partyUInfo := lengthPrefixed(apuData)
	partyVInfo := lengthPrefixed(apvData)

	// Encode output size in bits for suppPubInfo
	suppPubInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(suppPubInfo, uint32(keySize)*8)

	// Validate that the public key is on the same curve as the private key
	if !privateKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, errors.New("public key is not on the same curve as the private key")
	}

	// Calculate shared secret Z
	sharedX, _ := privateKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Ensure sharedSecret is padded to the correct size for the curve
	curveSize := curveCoordinateSize(privateKey.Curve)
	if len(sharedSecret) < curveSize {
		paddedSecret := make([]byte, curveSize)
		copy(paddedSecret[curveSize-len(sharedSecret):], sharedSecret)
		sharedSecret = paddedSecret
	}

	// Create a KDF reader with SHA-256
	kdfReader := newKDF(crypto.SHA256, sharedSecret, algorithmID, partyUInfo, partyVInfo, suppPubInfo, nil)
	derivedKey := make([]byte, keySize)

	// Read from the KDF into the derivedKey slice
	if _, err := kdfReader.Read(derivedKey); err != nil {
		return nil, fmt.Errorf("failed to read from KDF: %w", err)
	}

	return derivedKey, nil
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

// Encrypts a given plaintext using AES-GCM with an IV and AAD, returning the IV, tag, and ciphertext.
func encryptAESGCMWithIVAndAAD(key, plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a GCM block cipher mode instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a nonce (IV) for AES-GCM; it must be 12 bytes for optimal security
	iv := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, err
	}

	// Encrypt the plaintext with the IV and AAD
	ciphertext := aesGCM.Seal(nil, iv, plaintext, aad)

	// Extract the tag from the end of the ciphertext
	tag := ciphertext[len(ciphertext)-aesGCM.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-aesGCM.Overhead()]

	return iv, tag, ciphertext, nil
}

// Decrypts the ciphertext using AES-GCM with a provided IV, tag, and AAD.
func decryptAESGCMWithIVAndAAD(key, iv, tag, ciphertext, aad []byte) (string, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a GCM block cipher mode instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Combine the ciphertext and tag for decryption
	ciphertextWithTag := append(ciphertext, tag...)

	// Decrypt the ciphertext with the provided IV and AAD
	plaintext, err := aesGCM.Open(nil, iv, ciphertextWithTag, aad)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
