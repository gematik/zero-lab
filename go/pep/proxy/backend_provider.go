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

	"golang.org/x/oauth2"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oauth/providers"
)

// providerBackend drives oidc.Client providers (standard OIDC; OIDF and idpd also implement oidc.Client)
// directly and issues a local session — pep acts as the authorization server itself, no upstream PDP.
//
// Static providers (plain OIDC, idpd) are pre-constructed in byIssuer/order. An optional OIDF relying
// party resolves federation issuers dynamically (rp.NewClient(issuer)) and contributes its federation IdP
// list to the chooser; it also serves its entity statement at /.well-known/openid-federation.
type providerBackend struct {
	set *providers.Set
}

// NewProviderBackend returns the Backend that drives the providers of set directly and keeps their tokens
// in the local session.
func NewProviderBackend(set *providers.Set) Backend {
	return &providerBackend{set: set}
}

func (b *providerBackend) get(issuer string) (oidc.Client, error) {
	if issuer == "" {
		return b.set.Default()
	}
	return b.set.Client(issuer)
}

func providerOf(info providers.Info) Provider {
	return Provider{Issuer: info.Issuer, Name: info.Name, LogoURI: info.LogoURI, Type: info.Type}
}

func (b *providerBackend) DefaultIssuer() string {
	// Only auto-start when there is exactly one static provider and no federation to choose from.
	if clients := b.set.Clients(); b.set.Federation() == nil && len(clients) == 1 {
		return clients[0].Issuer()
	}
	return ""
}

func (b *providerBackend) Providers(_ context.Context) ([]Provider, error) {
	infos, err := b.set.Providers()
	if err != nil {
		return nil, err
	}
	out := make([]Provider, 0, len(infos))
	for _, info := range infos {
		out = append(out, providerOf(info))
	}
	return out, nil
}

func (b *providerBackend) StartLogin(_ context.Context, sess *Session, idpIss, _ string) (LoginStart, error) {
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
	// Pick the front-end flow: idpd's authenticator:// deep link → a wait page that opens the app and
	// polls; OIDF's PAR URL → the decoupled QR; everything else → a plain redirect.
	mode := "redirect"
	switch {
	case strings.HasPrefix(authURL, "authenticator://"):
		mode = "authenticator"
	case providers.TypeOf(c) == "oidf":
		mode = "decoupled"
	}
	p := providerOf(providers.InfoOf(c))
	return LoginStart{AuthURL: authURL, Mode: mode, Provider: &p}, nil
}

func (b *providerBackend) Complete(_ context.Context, sess *Session, code string) error {
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
func (b *providerBackend) FreshAccessToken(_ context.Context, sess *Session) (string, error) {
	return sess.AccessToken, nil
}

// entityStatementServer is a federation's relying party, which has an entity statement to serve.
type entityStatementServer interface {
	Serve(w http.ResponseWriter, r *http.Request)
}

// proxyRoutes serves the OIDF relying-party entity statement so the federation (and the OPs) can resolve
// this proxy as a relying party.
func (b *providerBackend) proxyRoutes() []proxyRoute {
	server, ok := b.set.Federation().(entityStatementServer)
	if !ok {
		return nil
	}
	return []proxyRoute{{
		Pattern: "GET /.well-known/openid-federation",
		Handler: http.HandlerFunc(server.Serve),
	}}
}
