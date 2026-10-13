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

package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

type Client interface {
	Issuer() string
	ClientID() string
	Name() string
	LogoURI() string
	RedirectURI() string
	AuthenticationURL(state, nonce, verifier string, options ...Option) (string, error)
	ExchangeForIdentity(code, verifier string, options ...Option) (*TokenResponse, error)
}

type Option any

// Allows for setting an alternate redirect URI (redirect_uri) for the authorization request.
type WithAlternateRedirectURI string

type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope"`
	RefreshToken string    `json:"refresh_token"`
	IDTokenRaw   string    `json:"id_token"`
	IDToken      jwt.Token `json:"-"`
}

func (t *TokenResponse) Claims(claims any) error {
	if t.IDTokenRaw == "" {
		return fmt.Errorf("ID token is empty")
	}
	claimsRaw := strings.Split(t.IDTokenRaw, ".")[1]

	claimsBytes, err := base64.RawURLEncoding.DecodeString(claimsRaw)
	if err != nil {
		return fmt.Errorf("decoding ID claims: %w", err)
	}

	if err := json.Unmarshal(claimsBytes, claims); err != nil {
		return fmt.Errorf("unmarshal claims: %w", err)
	}

	return nil
}
