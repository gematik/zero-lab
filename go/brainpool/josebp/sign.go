package josebp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/gematik/zero-lab/go/brainpool"
)

type JWT struct {
	Raw []byte
	//lint:ignore ST1003 exported since v1; the Go-style name would break the module's API
	HeadersJson []byte
	//lint:ignore ST1003 exported since v1; the Go-style name would break the module's API
	PayloadJson []byte
	Signature   []byte
	Headers     map[string]any
	Claims      map[string]any
}

type JWTBuilder struct {
	headers map[string]any
	claims  map[string]any
}

func NewJWTBuilder() *JWTBuilder {
	return &JWTBuilder{
		headers: make(map[string]any),
		claims:  make(map[string]any),
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
	headersJSON, err := json.Marshal(b.headers)
	if err != nil {
		return nil, fmt.Errorf("marshaling headers: %w", err)
	}

	claimsJSON, err := json.Marshal(b.claims)
	if err != nil {
		return nil, fmt.Errorf("marshaling claims: %w", err)
	}

	payload := base64.RawURLEncoding.AppendEncode(nil, headersJSON)
	payload = append(payload, '.')
	payload = base64.RawURLEncoding.AppendEncode(payload, claimsJSON)

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
