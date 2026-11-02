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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	defaultHTTPTimeout = 30 * time.Second
	// defaultAcceptableSkew is the RP/IdP clock-skew tolerance applied to the id_token's iat/exp/nbf when
	// Config.AcceptableSkew is unset. One minute is the common best-practice default: enough for real clock
	// drift + network latency, small enough to keep the replay window tight.
	defaultAcceptableSkew = time.Minute
)

// Config configures a client for the OpenID provider that publishes its discovery document under Issuer.
type Config struct {
	Issuer       string       `yaml:"issuer"`
	ClientID     string       `yaml:"client_id"`
	ClientSecret SecretString `yaml:"client_secret"`
	RedirectURI  string       `yaml:"redirect_uri"`
	Scopes       []string     `yaml:"scopes"`
	LogoURI      string       `yaml:"logo_uri"`
	Name         string       `yaml:"name"`

	// AcceptableSkew is the clock-skew tolerance for id_token iat/exp/nbf validation. 0 = defaultAcceptableSkew.
	AcceptableSkew time.Duration `yaml:"acceptable_skew"`

	// HTTPClient is used for discovery, the key cache, and token exchange. Not serialized; supplied
	// programmatically. When nil, a client with a default timeout is created.
	HTTPClient *http.Client `yaml:"-"`
}

type client struct {
	cfg               Config
	httpClient        *http.Client
	discoveryDocument *DiscoveryDocument
	keyCache          *keySetCache
}

// NewClient fetches the provider's discovery document and signing keys and returns a client for it, so the
// provider has to be reachable.
func NewClient(cfg Config) (Client, error) {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	c := &client{
		cfg:        cfg,
		httpClient: httpClient,
	}

	var err error
	c.discoveryDocument, err = FetchDiscoveryDocument(cfg.Issuer, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}

	c.keyCache = newKeySetCache(c.discoveryDocument.JwksURI, httpClient)
	if _, err := c.keyCache.keySet(context.Background(), ""); err != nil {
		return nil, fmt.Errorf("failed to fetch signing keys: %w", err)
	}

	return c, nil
}

func (c *client) DiscoveryDocument() *DiscoveryDocument {
	return c.discoveryDocument
}

func (c *client) AuthenticationURL(_ context.Context, login Login) (string, error) {
	query := AuthorizationQuery(c.cfg.ClientID, c.cfg.RedirectURI, c.cfg.Scopes, login)
	return c.discoveryDocument.AuthorizationEndpoint + "?" + query.Encode(), nil
}

func (c *client) Exchange(ctx context.Context, login Login, code string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret.Value())
	form.Set("code", code)
	form.Set("redirect_uri", login.RedirectFor(c.cfg.RedirectURI))
	form.Set("grant_type", "authorization_code")
	form.Set("code_verifier", login.Verifier)

	response, err := PostForm(ctx, c.httpClient, c.discoveryDocument.TokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("unable to exchange code for token: %w", err)
	}
	if response.Status != http.StatusOK {
		oidcErr := new(Error)
		if err := json.Unmarshal(response.Body, oidcErr); err != nil {
			return nil, fmt.Errorf("unable to decode error: %w", err)
		}
		return nil, oidcErr
	}
	tokenResponse, err := ParseTokenResponse(response.Body)
	if err != nil {
		return nil, err
	}
	if err := c.verifyIDToken(ctx, login, tokenResponse); err != nil {
		return nil, err
	}
	return tokenResponse, nil
}

// verifyIDToken verifies the ID token against the keys of the discovery document. The keys need not state an alg,
// as Entra ID's do not; the token has to, and the key has to fit it.
func (c *client) verifyIDToken(ctx context.Context, login Login, response *TokenResponse) error {
	skew := c.cfg.AcceptableSkew
	if skew <= 0 {
		skew = defaultAcceptableSkew
	}
	keysFor := func(kid string) (*jose.JSONWebKeySet, error) {
		return c.keyCache.keySet(ctx, kid)
	}
	payload, err := verifyJWS(response.IDTokenRaw, keysFor, VerifyOptions{})
	if err == nil {
		err = IDTokenChecks{
			Issuer:   c.discoveryDocument.Issuer,
			ClientID: c.cfg.ClientID,
			Nonce:    login.Nonce,
			Now:      time.Now(),
			Skew:     skew,
		}.Validate(payload)
	}
	if err != nil {
		slog.Error("verify id_token", "error", err, "jwks_uri", c.discoveryDocument.JwksURI)
		return fmt.Errorf("verify id_token: %w", err)
	}
	return nil
}

func (c *client) Issuer() string {
	return c.discoveryDocument.Issuer
}

// Validate reports a missing required field.
func (c Config) Validate() error {
	switch {
	case c.Issuer == "":
		return errors.New("issuer is required")
	case c.ClientID == "":
		return errors.New("client_id is required")
	case c.ClientSecret.Value() == "":
		return errors.New("client_secret is required")
	case c.RedirectURI == "":
		return errors.New("redirect_uri is required")
	}
	return nil
}
