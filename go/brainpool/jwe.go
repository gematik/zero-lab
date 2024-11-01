package brainpool

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

func (b *JWEBuilder) Header(key string, value interface{}) *JWEBuilder {
	b.headers[key] = value
	return b
}

func (b *JWEBuilder) Plaintext(plaintext []byte) *JWEBuilder {
	b.plaintext = plaintext
	return b
}

func (b *JWEBuilder) EncryptECDHES(recipient interface{}) ([]byte, error) {
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

	cek := DeriveECDHES("A256GCM", []byte{}, []byte{}, ephemeralKey, recipientKey, 32)

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
