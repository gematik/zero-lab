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

	"github.com/gematik/zero-lab/go/libzero/oauth2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// OpenidProviderInfo represents the information about an OpenID Provider
type OpenidProviderInfo struct {
	Issuer  string `json:"iss"`
	LogoURI string `json:"logo_uri"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

type Config struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURI  string   `yaml:"redirect_uri"`
	Scopes       []string `yaml:"scopes"`
	LogoURI      string   `yaml:"logo_uri"`
	Name         string   `yaml:"name"`
}

type Client interface {
	oauth2.Client
	ParseIDToken(response *oauth2.TokenResponse) (jwt.Token, error)
	Issuer() string
	ClientID() string
	Name() string
	LogoURI() string
}

type client struct {
	cfg               Config
	discoveryDocument *DiscoveryDocument
	keyCache          *jwk.Cache
}

func NewClient(cfg Config) (Client, error) {
	c := &client{
		cfg:               cfg,
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
	return c.cfg.ClientID
}

func (c *client) RedirectURI() string {
	return c.cfg.RedirectURI
}

func (c *client) DiscoveryDocument() *DiscoveryDocument {
	return c.discoveryDocument
}

func (c *client) AuthCodeURL(state, nonce, verifier string, opts ...oauth2.ParameterOption) (string, error) {
	codeChallenge := oauth2.S256ChallengeFromVerifier(verifier)
	query := url.Values{}
	query.Add("client_id", c.cfg.ClientID)
	query.Add("redirect_uri", c.cfg.RedirectURI)
	query.Add("response_type", "code")
	query.Add("scope", strings.Join(c.cfg.Scopes, " "))
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
	params.Set("client_id", c.cfg.ClientID)
	params.Set("client_secret", c.cfg.ClientSecret)
	params.Set("code", code)
	params.Set("redirect_uri", c.cfg.RedirectURI)
	params.Set("grant_type", "authorization_code")
	params.Set("code_verifier", codeVerifier)

	for _, opt := range opts {
		opt(params)
	}

	slog.Debug("Exchanging code for token", "url", c.discoveryDocument.TokenEndpoint, "params", params)

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
		slog.Error("unable to exchange code for token", "error", oidcErr)
		return nil, &oidcErr
	}

	var tokenResponse oauth2.TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		// ugly fallback to workaround EntraID insonstency with expires_in
		fallbackTokenResponse := struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in,string"`
			Scope        string `json:"scope"`
			RefreshToken string `json:"refresh_token"`
			IDToken      string `json:"id_token"`
		}{}
		err = json.Unmarshal(body, &fallbackTokenResponse)
		if err != nil {
			slog.Error("unable to decode token response", "error", err, "body", string(body))
			return nil, fmt.Errorf("unable to decode token response: %w", err)
		} else {
			tokenResponse.AccessToken = fallbackTokenResponse.AccessToken
			tokenResponse.TokenType = fallbackTokenResponse.TokenType
			tokenResponse.ExpiresIn = fallbackTokenResponse.ExpiresIn
			tokenResponse.Scope = fallbackTokenResponse.Scope
			tokenResponse.RefreshToken = fallbackTokenResponse.RefreshToken
			tokenResponse.IDToken = fallbackTokenResponse.IDToken
		}
	}

	return &tokenResponse, nil
}

// Parses and verifies an ID token against the keys from the discovery document.
func (c *client) ParseIDToken(response *oauth2.TokenResponse) (jwt.Token, error) {
	keySet, err := c.keyCache.Get(context.Background(), c.discoveryDocument.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("unable to get key set: %w", err)
	}

	token, err := jwt.ParseString(
		response.IDToken,
		jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)), // Azure AD does not include alg in ID token header
		jwt.WithIssuer(c.discoveryDocument.Issuer),
		jwt.WithAudience(c.cfg.ClientID),
		jwt.WithRequiredClaim("nonce"),
		//jwt.WithRequiredClaim("iat"),
		jwt.WithRequiredClaim("exp"),
	)
	if err != nil {
		// ugly fallback to workaround EntraID using RSA keys

		slog.Error("unable to parse id token", "error", err, "token", response.IDToken, "keySet", keySet, "jwksUri", c.discoveryDocument.JwksURI)
		return nil, fmt.Errorf("unable to parse id token: %w", err)
	}
	return token, nil
}

func (c *client) Issuer() string {
	return c.discoveryDocument.Issuer
}

func (c *client) Name() string {
	return c.cfg.Name
}

func (c *client) LogoURI() string {
	return c.cfg.LogoURI
}
