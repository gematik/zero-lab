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

package oidf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
)

// CodeChallengeMethod is a PKCE code_challenge_method (RFC 7636 §4.3).
type CodeChallengeMethod string

const (
	// CodeChallengeMethodS256 is the only method this package sends.
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

// RelyingPartyClient is an openid.Client for one OpenID provider of the federation; RelyingParty.NewClient
// creates it.
type RelyingPartyClient struct {
	rp          *RelyingParty
	op          *EntityStatement
	metadata    *OpenIDProviderMetadata
	scopes      []string
	redirectURI string
	jwks        *jose.JSONWebKeySet
}

// AuthenticationURL pushes the authorization request (PAR) and gives the URL that carries its request_uri.
func (c *RelyingPartyClient) AuthenticationURL(ctx context.Context, login openid.Login) (string, error) {
	form := openid.AuthorizationQuery(c.rp.ClientID(), c.redirectURI, c.scopes, login)
	form.Set("acr_values", "gematik-ehealth-loa-high")

	endpoint := c.op.Metadata.OpenidProvider.PushedAuthorizationRequestEndpoint
	response, err := openid.PostForm(ctx, c.rp.httpClient, endpoint, form)
	if err != nil {
		return "", fmt.Errorf("unable to do PAR request: %w", err)
	}
	if response.Status != http.StatusCreated {
		return "", fmt.Errorf("PAR: unexpected status %d: %w", response.Status, parseErrorResponse(bytes.NewReader(response.Body), endpoint))
	}
	var pushed pushedAuthorizationResponse
	if err := json.Unmarshal(response.Body, &pushed); err != nil {
		return "", fmt.Errorf("unable to read PAR response body: %w", err)
	}

	params := url.Values{}
	params.Add("request_uri", pushed.RequestURI)
	params.Add("client_id", c.rp.ClientID())
	return c.op.Metadata.OpenidProvider.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// Exchange redeems the authorization code over mutual TLS, decrypts the JWE id_token with the
// relying party's encryption key and verifies its signature against the provider's signed JWKS, its expiry
// and its audience against the client_id. A provider's rejection is
// returned as *Error.
func (c *RelyingPartyClient) Exchange(ctx context.Context, login openid.Login, code string) (*openid.TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", login.RedirectFor(c.redirectURI))
	form.Set("client_id", c.rp.ClientID())
	form.Set("code_verifier", login.Verifier)

	response, err := openid.PostForm(ctx, c.rp.httpClient, c.op.Metadata.OpenidProvider.TokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("unable to do token request: %w", err)
	}
	if response.Status != http.StatusOK {
		var oidcErr Error
		if err := json.Unmarshal(response.Body, &oidcErr); err != nil {
			return nil, fmt.Errorf("unable to decode error: %w", err)
		}
		return nil, &oidcErr
	}
	tokenResponse, err := openid.ParseTokenResponse(response.Body)
	if err != nil {
		return nil, err
	}

	decryptedIDToken, err := c.decryptIDToken(tokenResponse.IDTokenRaw)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt id_token: %w", err)
	}

	tokenResponse.IDTokenRaw = string(decryptedIDToken)

	if err := c.verifyIDToken(login, tokenResponse); err != nil {
		return nil, fmt.Errorf("unable to parse id_token: %w", err)
	}

	return tokenResponse, nil
}

// decryptIDToken takes only what buildMetadata registers the relying party for: id_token_encrypted_response_alg
// ECDH-ES and id_token_encrypted_response_enc A256GCM.
func (c *RelyingPartyClient) decryptIDToken(raw string) ([]byte, error) {
	encrypted, err := jose.ParseEncryptedCompact(raw, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, err
	}
	return encrypted.Decrypt(c.rp.encPrivateKey)
}

func (c *RelyingPartyClient) verifyIDToken(login openid.Login, response *openid.TokenResponse) error {
	payload, err := openid.VerifyJWS([]byte(response.IDTokenRaw), c.jwks, memberKeys)
	if err != nil {
		return fmt.Errorf("unable to parse token: %w", err)
	}
	checks := openid.IDTokenChecks{Issuer: c.op.Issuer, ClientID: c.rp.ClientID(), Nonce: login.Nonce, Now: time.Now()}
	if err := checks.Validate(payload); err != nil {
		return fmt.Errorf("unable to parse token: %w", err)
	}
	return nil
}

// Issuer returns the issuer named in the provider's entity statement.
func (c *RelyingPartyClient) Issuer() string {
	return c.op.Issuer
}
