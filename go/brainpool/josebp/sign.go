// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package josebp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/gematik/zero-lab/go/brainpool"
)

// JWT is a parsed compact JWS: the raw token, its decoded header and payload
// JSON, the raw r‖s signature and the unmarshaled header and claims.
type JWT struct {
	Raw         []byte
	HeadersJSON []byte
	PayloadJSON []byte
	Signature   []byte
	Headers     map[string]any
	Claims      map[string]any
}

// JWTBuilder collects header parameters and claims for a token signed with Sign.
type JWTBuilder struct {
	headers map[string]any
	claims  map[string]any
}

// NewJWTBuilder returns a builder with an empty header and no claims.
func NewJWTBuilder() *JWTBuilder {
	return &JWTBuilder{
		headers: make(map[string]any),
		claims:  make(map[string]any),
	}
}

// Header sets a JOSE header parameter.
func (b *JWTBuilder) Header(key string, value any) *JWTBuilder {
	b.headers[key] = value
	return b
}

// Claim sets a claim of the payload.
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

	payload = append(payload, '.')
	return base64.RawURLEncoding.AppendEncode(payload, signature), nil
}
