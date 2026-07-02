package josebp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/gematik/zero-lab/go/brainpool"
)

type Headers map[string]any
type Claims map[string]any

type JWT struct {
	Raw         []byte
	HeadersJson []byte
	PayloadJson []byte
	Signature   []byte
	Headers     Headers
	Claims      Claims
}

type JWTBuilder struct {
	headers Headers
	claims  Claims
}

func NewJWTBuilder() *JWTBuilder {
	return &JWTBuilder{
		headers: make(Headers),
		claims:  make(Claims),
	}
}

func (b *JWTBuilder) Header(key string, value any) *JWTBuilder {
	b.headers[key] = value
	return b
}

func (b *JWTBuilder) Claim(key string, value any) *JWTBuilder {
	b.claims[key] = value
	return b
}

// Sign produces a compact JWS over the builder's header + claims, hashing the signing input with
// hashFunc and signing the digest with signFunc (an opaque SignFunc — software key, smartcard, or
// connector). The signature is the raw fixed-width r‖s ECDSA encoding (RFC 7518 §3.4).
func (b *JWTBuilder) Sign(hashFunc hash.Hash, signFunc brainpool.SignFunc) ([]byte, error) {
	headersJson, err := json.Marshal(b.headers)
	if err != nil {
		return nil, fmt.Errorf("marshaling headers: %w", err)
	}

	claimsJson, err := json.Marshal(b.claims)
	if err != nil {
		return nil, fmt.Errorf("marshaling claims: %w", err)
	}

	payload := base64.RawURLEncoding.AppendEncode(nil, headersJson)
	payload = append(payload, '.')
	payload = base64.RawURLEncoding.AppendEncode(payload, claimsJson)

	hashFunc.Write(payload)
	digest := hashFunc.Sum(nil)
	signature, err := signFunc(digest)
	if err != nil {
		return nil, fmt.Errorf("signing payload: %w", err)
	}

	token := append(payload, '.')
	token = base64.RawURLEncoding.AppendEncode(token, signature)

	return token, nil
}
