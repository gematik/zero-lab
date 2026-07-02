//go:build mockidp

package mockidp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/oauth2"
)

// mockClient is the AS-side oidc.Client for the co-hosted mock OP. The PDP holds it in its provider registry
// like any upstream OP; ExchangeForIdentity does a real HTTP round-trip to the mock /token (co-hosted on the
// same server, reachable at runtime) and validates the returned id_token — exercising the genuine path.
type mockClient struct {
	issuer      string
	clientID    string
	redirectURI string
	pub         jwk.Key
	http        *http.Client
}

var _ oidc.Client = (*mockClient)(nil)

func (c *mockClient) Issuer() string      { return c.issuer }
func (c *mockClient) ClientID() string    { return c.clientID }
func (c *mockClient) Name() string        { return "Mock IdP (non-prod)" }
func (c *mockClient) LogoURI() string     { return "" }
func (c *mockClient) RedirectURI() string { return c.redirectURI }

func (c *mockClient) AuthenticationURL(state, nonce, verifier string, options ...oidc.Option) (string, error) {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", redirectURIFrom(c.redirectURI, options))
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", oauth2.S256ChallengeFromVerifier(verifier))
	q.Set("code_challenge_method", "S256")
	return c.issuer + "/auth?" + q.Encode(), nil
}

func (c *mockClient) ExchangeForIdentity(code, verifier string, options ...oidc.Option) (*oidc.TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("client_id", c.clientID)
	form.Set("redirect_uri", redirectURIFrom(c.redirectURI, options))

	hc := c.http
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.PostForm(c.issuer+"/token", form)
	if err != nil {
		return nil, fmt.Errorf("mock token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mock token endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	tr := new(oidc.TokenResponse)
	if err := json.Unmarshal(body, tr); err != nil {
		return nil, fmt.Errorf("decode mock token response: %w", err)
	}
	if _, err := jwt.ParseString(tr.IDTokenRaw,
		jwt.WithKey(jwa.ES256(), c.pub),
		jwt.WithIssuer(c.issuer),
		jwt.WithAudience(c.clientID),
		jwt.WithRequiredClaim("nonce"),
		jwt.WithRequiredClaim("exp"),
	); err != nil {
		return nil, fmt.Errorf("verify mock id_token: %w", err)
	}
	return tr, nil
}

func redirectURIFrom(def string, options []oidc.Option) string {
	for _, o := range options {
		if alt, ok := o.(oidc.WithAlternateRedirectURI); ok {
			return string(alt)
		}
	}
	return def
}
