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

// Package oidc is the client side of an OpenID Connect login by authorization code with PKCE, behind the Client
// interface that a federated provider's client implements as well.
package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Error is an OAuth 2.0 error response (RFC 6749 §5.2).
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// Login is what one login at a provider keeps from the authorization request to the token request. RFC 6749
// section 4.1.3 requires the token request to repeat the redirect_uri of the authorization request, so both get
// the same Login.
type Login struct {
	State    string
	Nonce    string
	Verifier string
	// RedirectURI overrides the client's configured one, for this login.
	RedirectURI string
}

// RedirectFor is the login's redirect URI, or the client's configured one if it has none.
func (l Login) RedirectFor(configured string) string {
	if l.RedirectURI != "" {
		return l.RedirectURI
	}
	return configured
}

// Client is the relying party's side of a login at one OpenID provider. What a chooser shows of it is in
// providers.Info.
type Client interface {
	Issuer() string
	// AuthenticationURL gives the URL that starts a login; a provider using PAR is called on the way.
	AuthenticationURL(ctx context.Context, login Login) (string, error)
	// Exchange redeems the code and verifies the ID token. A provider's refusal is returned as an error.
	Exchange(ctx context.Context, login Login, code string) (*TokenResponse, error)
}

// TokenResponse is a token endpoint response. IDTokenRaw has been verified once ExchangeForIdentity returned it.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDTokenRaw   string `json:"id_token"`
}

// Claims decodes the payload of IDTokenRaw into claims. It verifies nothing itself, so it is only meaningful on a
// response ExchangeForIdentity returned.
func (t *TokenResponse) Claims(claims any) error {
	if t.IDTokenRaw == "" {
		return errors.New("ID token is empty")
	}
	segments := strings.Split(t.IDTokenRaw, ".")
	if len(segments) != 3 {
		return errors.New("ID token is no compact JWS")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return fmt.Errorf("decoding ID claims: %w", err)
	}

	if err := json.Unmarshal(claimsBytes, claims); err != nil {
		return fmt.Errorf("unmarshal claims: %w", err)
	}

	return nil
}
