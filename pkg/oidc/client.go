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
	ClientID             string
	ClientSecret         string
	DiscoveryDocumentURL DiscoveryDocumentURL
	RedirectURL          string
	Scopes               []string
}

type Client struct {
	cfg               *Config
	discoveryDocument *DiscoveryDocument
	keyCache          *jwk.Cache
}

func NewClient(cfg *Config) (*Client, error) {
	c := &Client{
		cfg:               cfg,
		discoveryDocument: nil,
		keyCache:          nil,
	}

	var err error
	c.discoveryDocument, err = FetchDiscoveryDocument(cfg.DiscoveryDocumentURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document from %s: %w", cfg.DiscoveryDocumentURL, err)
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

func (c *Client) DiscoveryDocument() *DiscoveryDocument {
	return c.discoveryDocument
}

func (c *Client) AuthCodeURL(state, nonce, codeChallenge string, codeChallengeMethod oauth2.CodeChallengeMethod) string {
	query := url.Values{}
	query.Add("client_id", c.cfg.ClientID)
	query.Add("redirect_uri", c.cfg.RedirectURL)
	query.Add("response_type", "code")
	query.Add("scope", strings.Join(c.cfg.Scopes, " "))
	query.Add("state", state)
	query.Add("nonce", nonce)
	query.Add("code_challenge", codeChallenge)
	query.Add("code_challenge_method", string(codeChallengeMethod))

	return fmt.Sprintf("%s?%s", c.discoveryDocument.AuthorizationEndpoint, query.Encode())
}

func (c *Client) Exchange(code string, codeVerifier string) (*TokenResponse, error) {
	params := url.Values{}
	params.Set("client_id", c.cfg.ClientID)
	params.Set("client_secret", c.cfg.ClientSecret)
	params.Set("code", code)
	params.Set("redirect_uri", c.cfg.RedirectURL)
	params.Set("grant_type", "authorization_code")
	params.Set("code_verifier", codeVerifier)

	resp, err := http.PostForm(c.discoveryDocument.TokenEndpoint, params)
	if err != nil {
		return nil, fmt.Errorf("unable to exchange code for token: %w", err)
	}

	slog.Info("Exchange", "resp", resp)

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

	idToken, err := c.ParseIDToken(tokenResponse.IDToken)
	if err != nil {
		return nil, fmt.Errorf("unable to parse id token: %w", err)
	}

	return &TokenResponse{
		AccessToken: tokenResponse.AccessToken,
		TokenType:   tokenResponse.TokenType,
		ExpiresIn:   tokenResponse.ExpiresIn,
		Scopes:      strings.Split(tokenResponse.Scope, " "),
		IDToken:     idToken,
		IDTokenRaw:  tokenResponse.IDToken,
	}, nil
}

// Parses and verifies an ID token against the keys from the discovery document.
func (c *Client) ParseIDToken(serialized string) (jwt.Token, error) {
	keySet, err := c.keyCache.Get(context.Background(), c.discoveryDocument.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("unable to get key set: %w", err)
	}

	token, err := jwt.ParseString(
		serialized,
		jwt.WithKeySet(keySet),
		jwt.WithIssuer(c.discoveryDocument.Issuer),
		jwt.WithAudience(c.cfg.ClientID),
		jwt.WithRequiredClaim("nonce"),
		//jwt.WithRequiredClaim("iat"),
		jwt.WithRequiredClaim("exp"),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse id token: %w", err)
	}
	return token, nil
}

type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	Scopes       []string
	RefreshToken string
	IDToken      jwt.Token
	IDTokenRaw   string
}
