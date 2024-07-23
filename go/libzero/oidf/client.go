package oidf

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gematik/zero-lab/go/libzero/oauth2"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type RelyingPartyClient struct {
	rp          *RelyingParty
	op          *EntityStatement
	metadata    *OpenIDProviderMetadata
	scopes      []string
	redirectURI string
	jwks        jwk.Set
}

func (c *RelyingPartyClient) AuthCodeURL(state, nonce, verifier string, opts ...oauth2.ParameterOption) (string, error) {
	codeChallenge := oauth2.S256ChallengeFromVerifier(verifier)

	parData := url.Values{}
	parData.Add("scope", strings.Join(c.scopes, " "))
	parData.Add("acr_values", "gematik-ehealth-loa-high")
	parData.Add("response_type", "code")
	parData.Add("state", state)
	parData.Add("redirect_uri", c.redirectURI)
	parData.Add("code_challenge_method", string(oauth2.CodeChallengeMethodS256))
	parData.Add("nonce", nonce)
	parData.Add("client_id", c.rp.ClientID())
	parData.Add("code_challenge", codeChallenge)

	for _, opt := range opts {
		opt(parData)
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
		return "", fmt.Errorf("PAR: unexpected status '%s': %w", parResponse.Status, parseErrorResponse(parResponse.Body))
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

func (c *RelyingPartyClient) Exchange(code, verifier string, opts ...oauth2.ParameterOption) (*oauth2.TokenResponse, error) {
	tokenParams := url.Values{}
	tokenParams.Add("grant_type", "authorization_code")
	tokenParams.Add("code", code)
	tokenParams.Add("redirect_uri", c.redirectURI)
	tokenParams.Add("client_id", c.rp.ClientID())
	tokenParams.Add("code_verifier", verifier)

	for _, opt := range opts {
		opt(tokenParams)
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

	var rawTokenResponse oauth2.TokenResponse
	err = json.Unmarshal(body, &rawTokenResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to decode token response: %w", err)
	}

	decryptedIdToken, err := jwe.Decrypt([]byte(rawTokenResponse.IDToken), jwe.WithKey(jwa.ECDH_ES, c.rp.encPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt id_token: %w", err)
	}
	rawTokenResponse.IDToken = string(decryptedIdToken)

	return &rawTokenResponse, nil
}

func (c *RelyingPartyClient) ParseIDToken(response *oauth2.TokenResponse) (jwt.Token, error) {
	tokenJwt, err := jwt.Parse([]byte(response.IDToken), jwt.WithKeySet(c.jwks))
	if err != nil {
		return nil, fmt.Errorf("unable to parse token: %w", err)
	}
	// verify audience
	aud := tokenJwt.Audience()
	var matchedAud string
	for _, a := range aud {
		if a == c.rp.ClientID() {
			matchedAud = a
			break
		}
	}
	if matchedAud == "" {
		slog.Error("token audience does not match client_id", "aud", aud, "client_id", c.rp.ClientID())
		return nil, fmt.Errorf("token audience does not match client_id")
	}

	return tokenJwt, nil
}

func (c *RelyingPartyClient) ClientID() string {
	return c.rp.ClientID()
}

func (c *RelyingPartyClient) Issuer() string {
	return c.op.Issuer
}

func (c *RelyingPartyClient) Name() string {
	return c.metadata.OrganizationName
}

func (c *RelyingPartyClient) LogoURI() string {
	return c.metadata.LogoURI
}
