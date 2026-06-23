package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/segmentio/ksuid"
	"golang.org/x/oauth2"
)

// providerBackend drives oidc.Client providers (standard OIDC; OIDF and gemidp also implement oidc.Client)
// directly and issues a local session — pep acts as the authorization server itself, no upstream PDP.
type providerBackend struct {
	byIssuer map[string]oidc.Client
	order    []oidc.Client
}

// NewProviderBackend builds a direct-provider backend. The first client is the default when no idp_iss is
// given (the single-provider case).
func NewProviderBackend(clients ...oidc.Client) Backend {
	b := &providerBackend{byIssuer: make(map[string]oidc.Client, len(clients))}
	for _, c := range clients {
		b.byIssuer[c.Issuer()] = c
		b.order = append(b.order, c)
	}
	return b
}

func (b *providerBackend) get(issuer string) (oidc.Client, error) {
	if issuer == "" {
		if len(b.order) > 0 {
			return b.order[0], nil
		}
		return nil, fmt.Errorf("no providers configured")
	}
	if c, ok := b.byIssuer[issuer]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("unknown provider issuer %q", issuer)
}

func providerOf(c oidc.Client) Provider {
	return Provider{Issuer: c.Issuer(), Name: c.Name(), LogoURI: c.LogoURI(), Type: "oidc"}
}

func (b *providerBackend) Providers(ctx context.Context) ([]Provider, error) {
	out := make([]Provider, 0, len(b.order))
	for _, c := range b.order {
		out = append(out, providerOf(c))
	}
	return out, nil
}

func (b *providerBackend) StartLogin(ctx context.Context, sess *Session, idpIss, scope string) (LoginStart, error) {
	c, err := b.get(idpIss)
	if err != nil {
		return LoginStart{}, err
	}
	sess.IDPIss = c.Issuer()
	sess.State = ksuid.New().String()
	sess.Nonce = ksuid.New().String()
	sess.CodeVerifier = oauth2.GenerateVerifier()
	sess.CodeChallengeMethod = "S256"

	authURL, err := c.AuthenticationURL(sess.State, sess.Nonce, sess.CodeVerifier)
	if err != nil {
		return LoginStart{}, err
	}
	p := providerOf(c)
	return LoginStart{AuthURL: authURL, Mode: "redirect", Provider: &p}, nil
}

func (b *providerBackend) Complete(ctx context.Context, sess *Session, code string) error {
	c, err := b.get(sess.IDPIss)
	if err != nil {
		return err
	}
	tr, err := c.ExchangeForIdentity(code, sess.CodeVerifier)
	if err != nil {
		return err
	}
	var claims map[string]any
	if err := tr.Claims(&claims); err != nil {
		return fmt.Errorf("decode id_token claims: %w", err)
	}
	sess.Identity = claims
	sess.AccessToken = tr.AccessToken
	sess.RefreshToken = tr.RefreshToken
	if tr.ExpiresIn > 0 {
		sess.AccessTokenExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return nil
}

// FreshAccessToken returns the stored token; direct providers are not refreshed in S1.
func (b *providerBackend) FreshAccessToken(ctx context.Context, sess *Session) (string, error) {
	return sess.AccessToken, nil
}

func (b *providerBackend) DPoPKey() jwk.Key { return nil }
