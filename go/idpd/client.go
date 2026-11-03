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

// Package idpd is a client of the gematik IDP-Dienst: Client is the relying party of its authorization
// code flow, Authenticator answers its challenge with a signature from a smart card or a software key.
package idpd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/brainpool/josebp"
	"github.com/gematik/zero-lab/go/openid"
)

// idTokenSkew is the clock skew tolerated on the iat, nbf and exp of an ID token.
const idTokenSkew = 5 * time.Minute

// Metadata is the OpenID Connect discovery document of the gematik IDP-Dienst.
type Metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	SigningKeyURI                     string   `json:"uri_puk_idp_sig"`
	EncryptionKeyURI                  string   `json:"uri_puk_idp_enc"`
}

// TokenKeyPayload is sent from the client to the gematik IDP-Dienst when exchanging the authorization code:
// TokenKey is the key the IDP-Dienst encrypts the tokens with.
type TokenKeyPayload struct {
	TokenKey     string `json:"token_key"`
	CodeVerifier string `json:"code_verifier"`
}

// ClientConfig of the gematik IDP-Dienst client
type ClientConfig struct {
	Environment       Environment `yaml:"environment"`
	BaseURL           string      `yaml:"base_url,omitempty"`
	Name              string      `yaml:"name"`
	LogoURI           string      `yaml:"logo_uri"`
	ClientID          string      `yaml:"client_id"`
	RedirectURI       string      `yaml:"redirect_uri"`
	Scopes            []string    `yaml:"scopes"`
	AuthenticatorMode bool        `yaml:"authenticator_mode"`
	UserAgent         string      `yaml:"user_agent"`

	// TrustBundlePath is the file `ti pki trust export` writes, for a site that cannot fetch for itself.
	TrustBundlePath string `yaml:"trust_bundle_path,omitempty"`
	// TrustFetch downloads the trust material from gematik's hosts instead; see [FetchingTrust].
	TrustFetch bool `yaml:"trust_fetch,omitempty"`

	// Trust replaces both. Not serialized; supplied programmatically.
	Trust CertificateTrust `yaml:"-"`

	// HTTPClient is used for metadata, key, and token requests. Not serialized; supplied
	// programmatically. When nil, a client with a default timeout is created. The configured
	// User-Agent is layered onto the client's transport either way.
	HTTPClient *http.Client `yaml:"-"`
}

// Client is a relying party of the gematik IDP-Dienst.
type Client struct {
	config      ClientConfig
	Environment Environment
	IDP         IDP
	Metadata    Metadata
	baseURL     string
	httpClient  *http.Client
	trust       CertificateTrust
}

// NewClientFromConfig creates a Client and fetches the discovery document, so the IDP-Dienst has to be
// reachable and its certificate valid (IDPV-001). There is no client without trust material (IDPV-003).
// ClientID, RedirectURI and at least one scope are required; BaseURL overrides the base URL of
// the Environment.
func NewClientFromConfig(config ClientConfig) (*Client, error) {
	if config.Environment == EnvironmentUnset {
		return nil, errors.New("environment is required: test, ref or prod")
	}

	if config.ClientID == "" {
		return nil, errors.New("client ID is required")
	}

	if config.RedirectURI == "" {
		return nil, errors.New("redirect URI is required")
	}

	if len(config.Scopes) == 0 {
		return nil, errors.New("at least one scope is required")
	}

	if config.UserAgent == "" {
		config.UserAgent = defaultUserAgent
	}

	var idp IDP
	if config.BaseURL != "" {
		idp = NewIDP(config.Environment, config.BaseURL)
	} else {
		idp = GetIDPByEnvironment(config.Environment)
	}

	baseURL := idp.baseURL

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	// layer the gematik User-Agent onto the chosen client without mutating the caller's
	decorated := *httpClient
	decorated.Transport = &transportAddUserAgent{transportOrDefault(httpClient.Transport), config.UserAgent}
	httpClient = &decorated

	trust := config.Trust
	if trust == nil {
		configured, err := trustFromConfig(config, httpClient)
		if err != nil {
			return nil, fmt.Errorf("IDP-Dienst trust: %w", err)
		}
		trust = configured
	}

	metadata, err := fetchMetadata(baseURL, httpClient, trust)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata: %w", err)
	}

	return &Client{
		config:      config,
		Environment: config.Environment,
		IDP:         idp,
		Metadata:    *metadata,
		baseURL:     baseURL,
		httpClient:  httpClient,
		trust:       trust,
	}, nil
}

// AuthenticationURL gives the URL that starts a login. In authenticator mode it is an authenticator:// link for
// the gematik Authenticator app.
func (c *Client) AuthenticationURL(_ context.Context, login openid.Login) (string, error) {
	query := openid.AuthorizationQuery(c.config.ClientID, c.config.RedirectURI, c.config.Scopes, login)
	authURL := c.Metadata.AuthorizationEndpoint + "?" + query.Encode()
	if c.config.AuthenticatorMode {
		return authenticatorURL(authURL)
	}
	return authURL, nil
}

func authenticatorURL(authURL string) (string, error) {
	challengePath, err := url.Parse(authURL)
	if err != nil {
		return "", fmt.Errorf("parsing challenge path: %w", err)
	}

	// TODO: make selection of SMC-B / HBA configurable
	challengePath.RawQuery += "&cardType=SMC-B&callback=DIRECT"

	query := url.Values{
		"challenge_path": {challengePath.String()},
	}

	return "authenticator://?" + query.Encode(), nil
}

// Exchange exchanges an authorization code and its PKCE verifier for the tokens and verifies the
// ID token, which the response has to have. openid.WithAlternateRedirectURI has to name the redirect URI the login used, if it replaced one.
func (c *Client) Exchange(ctx context.Context, login openid.Login, code string) (*openid.TokenResponse, error) {
	// 32 bytes random key to encrypt the token
	tokenKeyBytes := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, tokenKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("generating token key: %w", err)
	}

	idpEncKey, err := fetchEncryptionKey(ctx, c.Metadata.EncryptionKeyURI, c.httpClient)
	if err != nil {
		return nil, fmt.Errorf("fetching challenge encryption key: %w", err)
	}

	tokenKeyPayload := TokenKeyPayload{
		TokenKey:     base64.RawURLEncoding.EncodeToString(tokenKeyBytes),
		CodeVerifier: login.Verifier,
	}

	tokenKeyPayloadBytes, err := json.Marshal(tokenKeyPayload)
	if err != nil {
		return nil, fmt.Errorf("marshalling token key payload: %w", err)
	}

	encryptedTokenKeySerialized, err := josebp.NewJWEBuilder().
		Plaintext(tokenKeyPayloadBytes).
		EncryptECDHES(idpEncKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting token key payload: %w", err)
	}

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("client_id", c.config.ClientID)
	params.Set("redirect_uri", login.RedirectFor(c.config.RedirectURI))
	params.Set("code", code)
	params.Set("key_verifier", string(encryptedTokenKeySerialized))

	slog.Debug("Exchanging code for token", "url", c.Metadata.TokenEndpoint)

	response, err := openid.PostForm(ctx, c.httpClient, c.Metadata.TokenEndpoint, params)
	if err != nil {
		return nil, fmt.Errorf("unable to exchange code for token: %w", err)
	}
	if response.Status != http.StatusOK {
		return nil, parseErrorResponse(response.Status, bytes.NewReader(response.Body))
	}

	tokenResponse, err := unmarshalTokenResponse(bytes.NewReader(response.Body))
	if err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	// Without an ID token nothing about this login has been verified.
	if tokenResponse.IDTokenRaw == "" {
		return nil, errors.New("the token response has no ID token")
	}
	if tokenResponse.IDTokenRaw, err = decryptToken(tokenResponse.IDTokenRaw, tokenKeyBytes); err != nil {
		return nil, fmt.Errorf("decrypting ID token: %w", err)
	}
	if err = c.verifyIDToken(ctx, login, tokenResponse.IDTokenRaw); err != nil {
		return nil, fmt.Errorf("parsing ID token: %w", err)
	}

	if tokenResponse.AccessToken != "" {
		if tokenResponse.AccessToken, err = decryptToken(tokenResponse.AccessToken, tokenKeyBytes); err != nil {
			return nil, fmt.Errorf("decrypting access token: %w", err)
		}
	}

	return tokenResponse, nil
}

// decryptToken takes the one form the IDP-Dienst encrypts a token in under the 256-bit key this client sent it: dir
// with A256GCM.
func decryptToken(token string, key []byte) (string, error) {
	encrypted, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return "", fmt.Errorf("decrypting token: %w", err)
	}
	plaintext, err := encrypted.Decrypt(key)
	if err != nil {
		return "", fmt.Errorf("decrypting token: %w", err)
	}

	njwt := new(Njwt)
	err = json.Unmarshal(plaintext, njwt)
	if err != nil {
		return "", fmt.Errorf("parsing NJWT: %w", err)
	}

	return njwt.Njwt, nil
}

func (c *Client) verifyIDToken(ctx context.Context, login openid.Login, raw string) error {
	key, err := fetchSigningKey(ctx, c.Metadata.SigningKeyURI, c.httpClient, c.trust)
	if err != nil {
		return fmt.Errorf("fetching signing key: %w", err)
	}
	return checkIDToken(raw, key, openid.IDTokenChecks{
		Issuer:   c.Metadata.Issuer,
		ClientID: c.config.ClientID,
		Nonce:    login.Nonce,
		Now:      time.Now(),
		Skew:     idTokenSkew,
	})
}

// checkIDToken verifies the ID token with josebp, as go-jose cannot do Brainpool, and then the claims it signed. The
// IDP-Dienst signs BP256R1 only, while josebp would take any algorithm of the key's size.
func checkIDToken(raw string, key *josebp.JSONWebKey, checks openid.IDTokenChecks) error {
	token, err := josebp.ParseToken([]byte(raw), josebp.WithKey(key))
	if err != nil {
		return fmt.Errorf("parsing ID token: %w", err)
	}
	if alg := token.Headers["alg"]; alg != josebp.AlgorithmNameBP256R1 {
		return fmt.Errorf("ID token signed with alg %v, expected %s", alg, josebp.AlgorithmNameBP256R1)
	}
	if err := checks.Validate(token.PayloadJSON); err != nil {
		return fmt.Errorf("unable to parse ID token: %w", err)
	}
	return nil
}

// Issuer returns the issuer from the IDP-Dienst's discovery document.
func (c *Client) Issuer() string {
	return c.Metadata.Issuer
}

type transportAddUserAgent struct {
	Transport http.RoundTripper
	UserAgent string
}

func (t *transportAddUserAgent) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.UserAgent)
	return t.Transport.RoundTrip(req)
}

func unmarshalTokenResponse(r io.Reader) (*openid.TokenResponse, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	tokenResponse := new(openid.TokenResponse)
	if err = json.Unmarshal(data, tokenResponse); err != nil {
		return nil, fmt.Errorf("unmarshalling token response: %w", err)
	}

	return tokenResponse, nil
}

// trustFromConfig takes exactly one source, so nobody believes one is in force while the other is.
func trustFromConfig(config ClientConfig, httpClient *http.Client) (CertificateTrust, error) {
	if config.TrustFetch && config.TrustBundlePath != "" {
		return nil, errors.New("trust_fetch and trust_bundle_path exclude each other")
	}
	if config.TrustFetch {
		return NewFetchingTrust(config.Environment, httpClient)
	}
	return NewBundleTrust(config.Environment, config.TrustBundlePath, httpClient)
}
