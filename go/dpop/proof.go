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

package dpop

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

// The protocol's names.
const (
	// HeaderName is the request header carrying the proof (Section 4.1).
	HeaderName = "DPoP"
	// NonceHeaderName is the response header carrying a server's nonce (Sections 8, 9).
	NonceHeaderName = "DPoP-Nonce"
	// Scheme is the authentication scheme of DPoP-bound access tokens (Section 7.1).
	Scheme = "DPoP"
	// TokenType is the token_type of a DPoP-bound access token response (Section 5).
	TokenType = "DPoP"
	// JWTType is the typ header of a proof (Section 4.2).
	JWTType = "dpop+jwt"
)

// ProofOptions are the optional parts of a proof.
type ProofOptions struct {
	// AccessToken is the access token sent with the request; the proof then carries its hash
	// as ath (Sections 4.2, 7.1).
	AccessToken string
	// Nonce is the latest DPoP-Nonce the server supplied (Sections 4.2, 8, 9).
	Nonce string
	// Clock dates the proof (iat). Nil means the system clock.
	Clock Clock
}

// claims are a proof's payload (Section 4.2). jti, htm, htu and iat are required; ath and
// nonce only when an access token or a server nonce applies.
type claims struct {
	ID       string `json:"jti"`
	Method   string `json:"htm"`
	URI      string `json:"htu"`
	IssuedAt int64  `json:"iat"`
	ATH      string `json:"ath,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

// Proof returns a DPoP proof JWT (Section 4.2) for a request with method to target: typ
// dpop+jwt, the key's algorithm, its public key as jwk; jti from 130 random bits, htm the
// method, htu target without query and fragment, iat the clock's time, and ath and nonce
// from opts.
func (k *Key) Proof(method, target string, opts ProofOptions) (string, error) {
	if !isToken(method) {
		return "", errors.New("dpop: method is not an HTTP method token")
	}
	htu, err := normalizeHTU(target)
	if err != nil {
		return "", fmt.Errorf("dpop: target URI: %w", err)
	}
	if opts.Nonce != "" && !isNonce(opts.Nonce) {
		return "", errors.New("dpop: nonce is not 1*NQCHAR (Section 8.1)")
	}
	c := claims{
		// Section 4.2 asks for at least 96 bits of pseudorandom data; rand.Text has 130.
		ID:       rand.Text(),
		Method:   method,
		URI:      htu,
		IssuedAt: clockOrSystem(opts.Clock).Now().Unix(),
		Nonce:    opts.Nonce,
	}
	if opts.AccessToken != "" {
		c.ATH = AccessTokenHash(opts.AccessToken)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("dpop: encode claims: %w", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: k.alg, Key: opaqueSigner{k}},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(JWTType),
	)
	if err != nil {
		return "", fmt.Errorf("dpop: signer: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("dpop: sign proof: %w", err)
	}
	return jws.CompactSerialize()
}

// Sign adds a proof for req to its headers, replacing any earlier one so that the request
// carries exactly one (Section 4.3, check 1). With an access token in opts it also sets
// Authorization to the DPoP scheme (Section 7.1). req.URL must be absolute, as for a
// request an [http.Client] sends.
func (k *Key) Sign(req *http.Request, opts ProofOptions) error {
	if opts.AccessToken != "" && !isToken68(opts.AccessToken) {
		return errors.New("dpop: access token is not a token68 value (Section 7.1)")
	}
	method := req.Method
	if method == "" {
		// net/http sends an empty method as GET.
		method = http.MethodGet
	}
	proof, err := k.Proof(method, req.URL.String(), opts)
	if err != nil {
		return err
	}
	req.Header.Set(HeaderName, proof)
	if opts.AccessToken != "" {
		req.Header.Set("Authorization", Scheme+" "+opts.AccessToken)
	}
	return nil
}

// AccessTokenHash is ath for accessToken: the base64url encoding of the SHA-256 hash of its
// ASCII encoding (Section 4.2).
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
