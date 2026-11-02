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

package authzserver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ClientAssertionTypeJWTBearer is the client_assertion_type for private_key_jwt (RFC 7523 §2.2).
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec // a public URN from the RFC, not a credential

// ClientAssertionClaims are the claims of a private_key_jwt client assertion. Beyond the standard
// RFC 7523 claims it keeps the gematik extensions: a nonce (redeemed against the AS nonce service)
// and cnf.jkt (the client's DPoP key, to which the issued access token is sender-constrained).
type ClientAssertionClaims struct {
	Nonce string   `json:"nonce"`
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub"`
	Aud   []string `json:"aud"`
	Iat   int      `json:"iat"`
	Exp   int      `json:"exp"`
	Cnf   struct {
		Jkt string `json:"jkt"`
	} `json:"cnf"`
}

// Validate reports a missing required claim. It checks presence only: the signature, audience, lifetime and
// nonce are verified by verifyClient.
func (c *ClientAssertionClaims) Validate() error {
	for _, claim := range []struct {
		name    string
		present bool
	}{
		{"nonce", c.Nonce != ""},
		{"iss", c.Iss != ""},
		{"sub", c.Sub != ""},
		{"aud", len(c.Aud) > 0},
		{"iat", c.Iat != 0},
		{"exp", c.Exp != 0},
		{"cnf.jkt", c.Cnf.Jkt != ""},
	} {
		if !claim.present {
			return fmt.Errorf("claim %s is required", claim.name)
		}
	}
	return nil
}

// parseClientAssertionClaims decodes the claims of a compact JWT without verifying its signature.
func parseClientAssertionClaims(assertion string) (*ClientAssertionClaims, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) < 2 {
		return nil, errors.New("malformed client_assertion")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode client_assertion payload: %w", err)
	}
	claims := new(ClientAssertionClaims)
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, fmt.Errorf("unmarshal client_assertion claims: %w", err)
	}
	return claims, nil
}
