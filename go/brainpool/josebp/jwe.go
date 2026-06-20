package josebp

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
)

type JWEBuilder struct {
	headers   Headers
	plaintext []byte
}

func NewJWEBuilder() *JWEBuilder {
	return &JWEBuilder{
		headers: make(Headers),
	}
}

func (b *JWEBuilder) Header(key string, value any) *JWEBuilder {
	b.headers[key] = value
	return b
}

func (b *JWEBuilder) Plaintext(plaintext []byte) *JWEBuilder {
	b.plaintext = plaintext
	return b
}

// EncryptECDHES builds a compact JWE (alg=ECDH-ES direct, enc=A256GCM) for the recipient's
// Brainpool public key, as required by the gematik IDP-Dienst. The ephemeral public key (epk) is
// serialized via josebp.JSONWebKey, so it carries the Brainpool crv (e.g. "BP-256").
func (b *JWEBuilder) EncryptECDHES(recipient any) ([]byte, error) {
	var recipientKey *ecdsa.PublicKey
	switch recipient := recipient.(type) {
	case *ecdsa.PublicKey:
		recipientKey = recipient
	case *JSONWebKey:
		switch key := recipient.Key.(type) {
		case *ecdsa.PublicKey:
			recipientKey = key
		default:
			return nil, errors.New("unsupported key type")
		}
	default:
		return nil, errors.New("unsupported key type")
	}

	ephemeralKey, err := ecdsa.GenerateKey(recipientKey.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	cek, err := DeriveECDHES("A256GCM", []byte{}, []byte{}, ephemeralKey, recipientKey, 32)
	if err != nil {
		return nil, fmt.Errorf("deriving ECDHES: %w", err)
	}

	b.headers["alg"] = "ECDH-ES"
	b.headers["enc"] = "A256GCM"
	b.headers["epk"] = &JSONWebKey{
		Key: &ephemeralKey.PublicKey,
	}

	headersJson, err := json.Marshal(b.headers)
	if err != nil {
		return nil, fmt.Errorf("marshalling headers: %w", err)
	}

	aad := []byte(base64.RawURLEncoding.EncodeToString(headersJson))

	iv, tag, ciphertext, err := encryptAESGCMWithIVAndAAD(cek, b.plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypting with AES-GCM: %w", err)
	}

	// Compact serialization: header..iv.ciphertext.tag (empty encrypted-key for ECDH-ES direct).
	serialized := []byte(base64.RawURLEncoding.EncodeToString(headersJson))
	serialized = append(serialized, '.')
	serialized = append(serialized, '.')
	serialized = append(serialized, base64.RawURLEncoding.EncodeToString(iv)...)
	serialized = append(serialized, '.')
	serialized = append(serialized, base64.RawURLEncoding.EncodeToString(ciphertext)...)
	serialized = append(serialized, '.')
	serialized = append(serialized, base64.RawURLEncoding.EncodeToString(tag)...)

	return serialized, nil
}

// DeriveECDHES performs the ECDH-ES Concat KDF (RFC 7518 §4.6) over an elliptic curve.
func DeriveECDHES(algorithm string, apuData, apvData []byte, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, keySize int) ([]byte, error) {
	if keySize > 1<<16 {
		return nil, errors.New("key size too large: must be less than or equal to 64 KiB")
	}

	algorithmID := lengthPrefixed([]byte(algorithm))
	partyUInfo := lengthPrefixed(apuData)
	partyVInfo := lengthPrefixed(apvData)

	suppPubInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(suppPubInfo, uint32(keySize)*8)

	if !privateKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, errors.New("public key is not on the same curve as the private key")
	}

	sharedX, _ := privateKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	sharedSecret := sharedX.Bytes()

	curveSize := curveCoordinateSize(privateKey.Curve)
	if len(sharedSecret) < curveSize {
		paddedSecret := make([]byte, curveSize)
		copy(paddedSecret[curveSize-len(sharedSecret):], sharedSecret)
		sharedSecret = paddedSecret
	}

	kdfReader := newKDF(crypto.SHA256, sharedSecret, algorithmID, partyUInfo, partyVInfo, suppPubInfo, nil)
	derivedKey := make([]byte, keySize)

	if _, err := kdfReader.Read(derivedKey); err != nil {
		return nil, fmt.Errorf("failed to read from KDF: %w", err)
	}

	return derivedKey, nil
}

func curveCoordinateSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

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

	if len(ctx.cache) > 0 {
		n := copy(out, ctx.cache)
		totalCopied += n
		ctx.cache = ctx.cache[n:]
		if totalCopied == len(out) {
			return totalCopied, nil
		}
	}

	for totalCopied < len(out) {
		ctx.hasher.Reset()

		counter := [4]byte{}
		binary.BigEndian.PutUint32(counter[:], ctx.i)
		_, _ = ctx.hasher.Write(counter[:])

		_, _ = ctx.hasher.Write(ctx.z)
		_, _ = ctx.hasher.Write(ctx.info)

		hash := ctx.hasher.Sum(nil)
		n := copy(out[totalCopied:], hash)
		totalCopied += n

		if n < len(hash) {
			ctx.cache = hash[n:]
		} else {
			ctx.cache = nil
		}

		ctx.i++
	}

	return totalCopied, nil
}

// encryptAESGCMWithIVAndAAD encrypts plaintext with AES-GCM, returning iv, tag, ciphertext.
func encryptAESGCMWithIVAndAAD(key, plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	iv := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, err
	}

	ciphertext := aesGCM.Seal(nil, iv, plaintext, aad)

	tag := ciphertext[len(ciphertext)-aesGCM.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-aesGCM.Overhead()]

	return iv, tag, ciphertext, nil
}

// decryptAESGCMWithIVAndAAD decrypts AES-GCM given iv, tag, ciphertext, and aad.
func decryptAESGCMWithIVAndAAD(key, iv, tag, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertextWithTag := append(ciphertext, tag...)

	plaintext, err := aesGCM.Open(nil, iv, ciphertextWithTag, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
