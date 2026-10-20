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

package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oidf"
	"golang.org/x/oauth2"
)

// providerBackend drives oidc.Client providers (standard OIDC; OIDF and gemidp also implement oidc.Client)
// directly and issues a local session — pep acts as the authorization server itself, no upstream PDP.
//
// Static providers (plain OIDC, gemidp) are pre-constructed in byIssuer/order. An optional OIDF relying
// party resolves federation issuers dynamically (rp.NewClient(issuer)) and contributes its federation IdP
// list to the chooser; it also serves its entity statement at /.well-known/openid-federation.
type providerBackend struct {
	byIssuer map[string]oidc.Client
	order    []oidc.Client
	rp       *oidf.RelyingParty
}

// ProviderOption configures a providerBackend.
type ProviderOption func(*providerBackend)

// WithOIDCClients adds pre-constructed providers (plain OIDC, gemidp). The first is the default when no
// idp_iss is given and no OIDF relying party is configured.
func WithOIDCClients(clients ...oidc.Client) ProviderOption {
	return func(b *providerBackend) {
		for _, c := range clients {
			b.byIssuer[c.Issuer()] = c
			b.order = append(b.order, c)
		}
	}
}

// WithRelyingParty enables OIDF: dynamic federation issuer resolution + the federation IdP list. The RP's
// own config supplies the redirect_uri (its redirect_uris[0] must be <public>/oauth2/callback).
func WithRelyingParty(rp *oidf.RelyingParty) ProviderOption {
	return func(b *providerBackend) { b.rp = rp }
}

func NewProviderBackend(opts ...ProviderOption) Backend {
	b := &providerBackend{byIssuer: make(map[string]oidc.Client)}
	for _, o := range opts {
		o(b)
	}
	return b
}

func (b *providerBackend) get(issuer string) (oidc.Client, error) {
	if issuer == "" {
		if len(b.order) > 0 {
			return b.order[0], nil
		}
		return nil, fmt.Errorf("no default provider configured; choose one")
	}
	if c, ok := b.byIssuer[issuer]; ok {
		return c, nil
	}
	if b.rp != nil {
		return b.rp.NewClient(issuer) // federation discovery
	}
	return nil, fmt.Errorf("unknown provider issuer %q", issuer)
}

// providerType classifies a resolved client for the chooser + the redirect-vs-decoupled decision.
func providerType(c oidc.Client) string {
	switch c.(type) {
	case *oidf.RelyingPartyClient:
		return "oidf"
	case *gemidp.Client:
		return "gemidp"
	default:
		return "oidc"
	}
}

func providerOf(c oidc.Client) Provider {
	return Provider{Issuer: c.Issuer(), Name: c.Name(), LogoURI: c.LogoURI(), Type: providerType(c)}
}

func (b *providerBackend) DefaultIssuer() string {
	// Only auto-start when there is exactly one static provider and no federation to choose from.
	if b.rp == nil && len(b.order) == 1 {
		return b.order[0].Issuer()
	}
	return ""
}

func (b *providerBackend) Providers(ctx context.Context) ([]Provider, error) {
	out := make([]Provider, 0, len(b.order))
	for _, c := range b.order {
		out = append(out, providerOf(c))
	}
	if b.rp != nil {
		idps, err := b.rp.Federation().FetchIdpList()
		if err != nil {
			return nil, fmt.Errorf("fetch federation idp list: %w", err)
		}
		for _, idp := range idps {
			out = append(out, Provider{Issuer: idp.Issuer, Name: idp.OrganizationName, LogoURI: idp.LogoURI, Type: "oidf"})
		}
	}
	return out, nil
}

func (b *providerBackend) StartLogin(ctx context.Context, sess *Session, idpIss, scope string) (LoginStart, error) {
	c, err := b.get(idpIss)
	if err != nil {
		return LoginStart{}, err
	}
	sess.IDPIss = c.Issuer()
	sess.State = uuid.NewV4().String()
	sess.Nonce = uuid.NewV4().String()
	sess.CodeVerifier = oauth2.GenerateVerifier()
	sess.CodeChallengeMethod = "S256"

	authURL, err := c.AuthenticationURL(sess.State, sess.Nonce, sess.CodeVerifier)
	if err != nil {
		return LoginStart{}, err
	}
	// Pick the front-end flow: gemidp's authenticator:// deep link → a wait page that opens the app and
	// polls; OIDF's PAR URL → the decoupled QR; everything else → a plain redirect.
	mode := "redirect"
	switch {
	case strings.HasPrefix(authURL, "authenticator://"):
		mode = "authenticator"
	case providerType(c) == "oidf":
		mode = "decoupled"
	}
	p := providerOf(c)
	return LoginStart{AuthURL: authURL, Mode: mode, Provider: &p}, nil
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

// FreshAccessToken returns the stored token; direct providers are not refreshed in S1/S2.
func (b *providerBackend) FreshAccessToken(ctx context.Context, sess *Session) (string, error) {
	return sess.AccessToken, nil
}

// proxyRoutes serves the OIDF relying-party entity statement so the federation (and the OPs) can resolve
// this proxy as a relying party.
func (b *providerBackend) proxyRoutes() []proxyRoute {
	if b.rp == nil {
		return nil
	}
	return []proxyRoute{{
		Pattern: "GET /.well-known/openid-federation",
		Handler: http.HandlerFunc(b.rp.Serve),
	}}
}
