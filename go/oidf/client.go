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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/oauth2"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

// CodeChallengeMethod is a PKCE code_challenge_method (RFC 7636 §4.3).
type CodeChallengeMethod string

const (
	// CodeChallengeMethodS256 is the only method this package sends.
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

// RelyingPartyClient is an oidc.Client for one OpenID provider of the federation; RelyingParty.NewClient
// creates it.
type RelyingPartyClient struct {
	rp          *RelyingParty
	op          *EntityStatement
	metadata    *OpenIDProviderMetadata
	scopes      []string
	redirectURI string
	jwks        jwk.Set
}

// AuthenticationURL pushes the authorization request to the provider's PAR endpoint (RFC 9126) over mutual
// TLS and returns the URL to send the user agent to. verifier is the PKCE code verifier.
func (c *RelyingPartyClient) AuthenticationURL(state, nonce, verifier string, options ...oidc.Option) (string, error) {
	codeChallenge := oauth2.S256ChallengeFromVerifier(verifier)

	parData := url.Values{}
	parData.Add("scope", strings.Join(c.scopes, " "))
	parData.Add("acr_values", "gematik-ehealth-loa-high")
	parData.Add("response_type", "code")
	parData.Add("state", state)
	parData.Add("redirect_uri", c.redirectURI)
	parData.Add("code_challenge_method", string(CodeChallengeMethodS256))
	parData.Add("nonce", nonce)
	parData.Add("client_id", c.rp.ClientID())
	parData.Add("code_challenge", codeChallenge)

	for _, option := range options {
		if opt, ok := option.(oidc.WithAlternateRedirectURI); ok {
			parData.Set("redirect_uri", string(opt))
		}
	}

	slog.Info("Issuing PAR request", "endpoint", c.op.Metadata.OpenidProvider.PushedAuthorizationRequestEndpoint, "params", parData)

	parRequest, err := http.NewRequest(
		http.MethodPost,
		c.op.Metadata.OpenidProvider.PushedAuthorizationRequestEndpoint,
		strings.NewReader(parData.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("unable to create PAR request: %w", err)
	}

	parRequest.Header.Add("Accept", "*/*")
	parRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	parResponse, err := c.rp.httpClient.Do(parRequest)
	if err != nil {
		return "", fmt.Errorf("unable to do PAR request: %w", err)
	}
	defer parResponse.Body.Close()

	if parResponse.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("PAR: unexpected status '%s': %w", parResponse.Status, parseErrorResponse(parResponse.Body, c.op.Metadata.OpenidProvider.PushedAuthorizationRequestEndpoint))
	}

	var parResp pushedAuthorizationResponse

	err = json.NewDecoder(parResponse.Body).Decode(&parResp)
	if err != nil {
		return "", fmt.Errorf("unable to read PAR response body: %w", err)
	}

	params := url.Values{}
	params.Add("request_uri", parResp.RequestURI)
	params.Add("client_id", c.rp.ClientID())

	return c.op.Metadata.OpenidProvider.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// ExchangeForIdentity redeems the authorization code over mutual TLS, decrypts the JWE id_token with the
// relying party's encryption key and verifies its signature against the provider's signed JWKS, its expiry
// and its audience against the client_id. Issuer and nonce are not checked here. A provider's rejection is
// returned as *Error.
func (c *RelyingPartyClient) ExchangeForIdentity(code, verifier string, options ...oidc.Option) (*oidc.TokenResponse, error) {
	tokenParams := url.Values{}
	tokenParams.Add("grant_type", "authorization_code")
	tokenParams.Add("code", code)
	tokenParams.Add("redirect_uri", c.redirectURI)
	tokenParams.Add("client_id", c.rp.ClientID())
	tokenParams.Add("code_verifier", verifier)

	for _, option := range options {
		if opt, ok := option.(oidc.WithAlternateRedirectURI); ok {
			tokenParams.Set("redirect_uri", string(opt))
		}
	}

	req, err := http.NewRequest(http.MethodPost, c.op.Metadata.OpenidProvider.TokenEndpoint, strings.NewReader(tokenParams.Encode()))
	if err != nil {
		return nil, fmt.Errorf("unable to create token request: %w", err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.rp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to do token request: %w", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var oidcErr Error
		err = json.Unmarshal(body, &oidcErr)
		if err != nil {
			return nil, fmt.Errorf("unable to decode error: %w", err)
		}
		return nil, &oidcErr
	}

	var tokenResponse oidc.TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to decode token response: %w", err)
	}

	decryptedIDToken, err := jwe.Decrypt([]byte(tokenResponse.IDTokenRaw), jwe.WithKey(jwa.ECDH_ES(), c.rp.encPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt id_token: %w", err)
	}

	tokenResponse.IDTokenRaw = string(decryptedIDToken)

	if tokenResponse.IDToken, err = c.parseIDToken(&tokenResponse); err != nil {
		return nil, fmt.Errorf("unable to parse id_token: %w", err)
	}

	return &tokenResponse, nil
}

func (c *RelyingPartyClient) parseIDToken(response *oidc.TokenResponse) (jwt.Token, error) {
	tokenJwt, err := jwt.Parse([]byte(response.IDTokenRaw), jwt.WithKeySet(c.jwks))
	if err != nil {
		return nil, fmt.Errorf("unable to parse token: %w", err)
	}
	// verify audience
	aud, ok := tokenJwt.Audience()
	if !ok {
		slog.Error("token audience not found", "aud", aud)
		return nil, errors.New("token audience not found")
	}
	var matchedAud string
	for _, a := range aud {
		if a == c.rp.ClientID() {
			matchedAud = a
			break
		}
	}
	if matchedAud == "" {
		slog.Error("token audience does not match client_id", "aud", aud, "client_id", c.rp.ClientID())
		return nil, errors.New("token audience does not match client_id")
	}

	return tokenJwt, nil
}

// ClientID returns the relying party's entity identifier, which is its OIDF client_id.
func (c *RelyingPartyClient) ClientID() string {
	return c.rp.ClientID()
}

// Issuer returns the issuer named in the provider's entity statement.
func (c *RelyingPartyClient) Issuer() string {
	return c.op.Issuer
}

// Name returns the provider's organization_name, for display.
func (c *RelyingPartyClient) Name() string {
	return c.metadata.OrganizationName
}

// LogoURI returns the provider's logo_uri, for display.
func (c *RelyingPartyClient) LogoURI() string {
	return c.metadata.LogoURI
}

// RedirectURI returns the first configured redirect URI, used unless a call overrides it with
// oidc.WithAlternateRedirectURI.
func (c *RelyingPartyClient) RedirectURI() string {
	return c.redirectURI
}
