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

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/oauth2"
)

type Config struct {
	Issuer       string       `yaml:"issuer" validate:"required"`
	ClientID     string       `yaml:"client_id" validate:"required"`
	ClientSecret SecretString `yaml:"client_secret" validate:"required"`
	RedirectURI  string       `yaml:"redirect_uri" validate:"required"`
	Scopes       []string     `yaml:"scopes"`
	LogoURI      string       `yaml:"logo_uri"`
	Name         string       `yaml:"name"`
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
	context := context.Background()
	c.keyCache, err = jwk.NewCache(context, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("failed to create key cache: %w", err)
	}

	c.keyCache.Register(context, c.discoveryDocument.JwksURI)
	_, err = c.keyCache.Refresh(context, c.discoveryDocument.JwksURI)
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

func (c *client) AuthenticationURL(state, nonce, verifier string, options ...Option) (string, error) {
	codeChallenge := oauth2.S256ChallengeFromVerifier(verifier)
	query := url.Values{}
	query.Add("client_id", c.cfg.ClientID)
	query.Add("redirect_uri", c.cfg.RedirectURI)
	query.Add("response_type", "code")
	query.Add("scope", strings.Join(c.cfg.Scopes, " "))
	query.Add("state", state)
	query.Add("nonce", nonce)
	query.Add("code_challenge", codeChallenge)
	query.Add("code_challenge_method", "S256")

	slog.Info("Using OP AuthorizationEndpoint", "url", c.discoveryDocument.AuthorizationEndpoint)

	for _, option := range options {
		switch opt := option.(type) {
		case WithAlternateRedirectURI:
			query.Set("redirect_uri", string(opt))
		}
	}

	return fmt.Sprintf("%s?%s", c.discoveryDocument.AuthorizationEndpoint, query.Encode()), nil
}

func (c *client) ExchangeForIdentity(code, verifier string, options ...Option) (*TokenResponse, error) {
	params := url.Values{}
	params.Set("client_id", c.cfg.ClientID)
	params.Set("client_secret", c.cfg.ClientSecret.Value())
	params.Set("code", code)
	params.Set("redirect_uri", c.cfg.RedirectURI)
	params.Set("grant_type", "authorization_code")
	params.Set("code_verifier", verifier)

	for _, option := range options {
		switch opt := option.(type) {
		case WithAlternateRedirectURI:
			params.Set("redirect_uri", string(opt))
		}
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
		oidcErr := new(Error)
		err = json.Unmarshal(body, &oidcErr)
		if err != nil {
			return nil, fmt.Errorf("unable to decode error: %w", err)
		}
		slog.Error("unable to exchange code for token", "error", oidcErr)
		return nil, oidcErr
	}

	tokenResponse := new(TokenResponse)

	err = json.Unmarshal(body, tokenResponse)
	if err != nil {
		// ugly fallback to workaround EntraID inconstency with expires_in
		fallbackTokenResponse := struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in,string"`
			Scope        string `json:"scope"`
			RefreshToken string `json:"refresh_token"`
			IDTokenRaw   string `json:"id_token"`
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
			tokenResponse.IDTokenRaw = fallbackTokenResponse.IDTokenRaw
		}
	}

	// Parse the ID token
	if tokenResponse.IDToken, err = c.parseIDToken(tokenResponse); err != nil {
		return nil, fmt.Errorf("unable to parse ID token: %w", err)
	}

	return tokenResponse, nil
}

// Parses and verifies an ID token against the keys from the discovery document.
func (c *client) parseIDToken(response *TokenResponse) (jwt.Token, error) {
	keySet, err := c.keyCache.Lookup(context.Background(), c.discoveryDocument.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("unable to get key set: %w", err)
	}

	token, err := jwt.ParseString(
		response.IDTokenRaw,
		jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)), // Azure AD does not include alg in ID token header
		jwt.WithIssuer(c.discoveryDocument.Issuer),
		jwt.WithAudience(c.cfg.ClientID),
		jwt.WithRequiredClaim("nonce"),
		//jwt.WithRequiredClaim("iat"),
		jwt.WithRequiredClaim("exp"),
	)
	if err != nil {
		slog.Error("unable to parse id token", "error", err, "id_token", response.IDTokenRaw, "keySet", keySet, "jwksUri", c.discoveryDocument.JwksURI)
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
