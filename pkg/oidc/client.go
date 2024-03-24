package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gematik/zero-lab/pkg/oauth2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

type Client interface {
	oauth2.Client
	Issuer() string
	ClientID() string
}

type client struct {
	Config            *Config
	discoveryDocument *DiscoveryDocument
	keyCache          *jwk.Cache
}

func NewClient(cfg *Config) (Client, error) {
	c := &client{
		Config:            cfg,
		discoveryDocument: nil,
		keyCache:          nil,
	}

	var err error
	discoveryDocumentUrl := cfg.Issuer + "/.well-known/openid-configuration"
	c.discoveryDocument, err = FetchDiscoveryDocument(discoveryDocumentUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document from %s: %w", discoveryDocumentUrl, err)
	}

	// prepare the auto-refreshing signing key cache
	c.keyCache = jwk.NewCache(context.Background())
	c.keyCache.Register(c.discoveryDocument.JwksURI, jwk.WithMinRefreshInterval(15*time.Minute))
	_, err = c.keyCache.Refresh(context.Background(), c.discoveryDocument.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signing keys: %w", err)
	}

	return c, nil
}

func (c *client) ClientID() string {
	return c.Config.ClientID
}

func (c *client) RedirectURI() string {
	return c.Config.RedirectURI
}

func (c *client) DiscoveryDocument() *DiscoveryDocument {
	return c.discoveryDocument
}

func (c *client) AuthCodeURL(state, nonce, verifier string, opts ...oauth2.ParameterOption) (string, error) {
	codeChallenge := oauth2.S256ChallengeFromVerifier(verifier)
	query := url.Values{}
	query.Add("client_id", c.Config.ClientID)
	query.Add("redirect_uri", c.Config.RedirectURI)
	query.Add("response_type", "code")
	query.Add("scope", strings.Join(c.Config.Scopes, " "))
	query.Add("state", state)
	query.Add("nonce", nonce)
	query.Add("code_challenge", codeChallenge)
	query.Add("code_challenge_method", string(oauth2.CodeChallengeMethodS256))

	for _, opt := range opts {
		opt(query)
	}

	slog.Info("Using OP AuthorizationEndpoint", "url", c.discoveryDocument.AuthorizationEndpoint)

	return fmt.Sprintf("%s?%s", c.discoveryDocument.AuthorizationEndpoint, query.Encode()), nil
}

func (c *client) Exchange(code string, codeVerifier string, opts ...oauth2.ParameterOption) (*oauth2.TokenResponse, error) {
	params := url.Values{}
	params.Set("client_id", c.Config.ClientID)
	params.Set("client_secret", c.Config.ClientSecret)
	params.Set("code", code)
	params.Set("redirect_uri", c.Config.RedirectURI)
	params.Set("grant_type", "authorization_code")
	params.Set("code_verifier", codeVerifier)

	for _, opt := range opts {
		opt(params)
	}

	resp, err := http.PostForm(c.discoveryDocument.TokenEndpoint, params)
	if err != nil {
		return nil, fmt.Errorf("unable to exchange code for token: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var oidcErr oauth2.Error
		err = json.Unmarshal(body, &oidcErr)
		if err != nil {
			return nil, fmt.Errorf("unable to decode error: %w", err)
		}
		return nil, &oidcErr
	}

	var tokenResponse oauth2.TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to decode token response: %w", err)
	}

	return &tokenResponse, nil
}

// Parses and verifies an ID token against the keys from the discovery document.
func (c *client) ParseIDToken(serialized string) (jwt.Token, error) {
	keySet, err := c.keyCache.Get(context.Background(), c.discoveryDocument.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("unable to get key set: %w", err)
	}

	token, err := jwt.ParseString(
		serialized,
		jwt.WithKeySet(keySet),
		jwt.WithIssuer(c.discoveryDocument.Issuer),
		jwt.WithAudience(c.Config.ClientID),
		jwt.WithRequiredClaim("nonce"),
		//jwt.WithRequiredClaim("iat"),
		jwt.WithRequiredClaim("exp"),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse id token: %w", err)
	}
	return token, nil
}

func (c *client) Issuer() string {
	return c.discoveryDocument.Issuer
}
