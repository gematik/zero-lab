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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/oauth"
)

var (
	_ Backend       = (*pdpBackend)(nil)
	_ dpopForwarder = (*pdpBackend)(nil)
)

// injectDPoP mints a fresh proof bound to the outbound request and attaches the DPoP-bound token, replacing
// any client Authorization. The proof is signed with the session's DPoP key (the token's cnf.jkt). This is the
// gateway's dpop inject, generalizing the former single /api proxy.
func (b *pdpBackend) injectDPoP(out *http.Request, sess *Session, token string) error {
	key, err := parseSessionDPoPKey(sess.DPoPKeyJWK)
	if err != nil {
		return err
	}
	proof, err := b.signer.dpopProof(out, token, key)
	if err != nil {
		return err
	}
	out.Header.Set("Authorization", "DPoP "+token)
	out.Header.Set(dpop.HeaderName, proof)
	return nil
}

// PDPConfig configures the pdpBackend: pep as a confidential OAuth client of the PDP (the gematik AS).
type PDPConfig struct {
	ASIssuer    string           // the PDP authorization server (login + identity)
	ClientID    string           // pep's registered client_id
	SigningKey  *jose.JSONWebKey // private_key_jwt signing key (loaded from a *_PATH file); its kid names it in the assertion header
	RedirectURI string           // default <public>/oauth2/callback
	Scopes      []string
	HTTPClient  *http.Client
}

// asMetadata is the subset of RFC 8414 authorization-server metadata the backend needs.
type asMetadata struct {
	Issuer                             string `json:"issuer"`
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	IntrospectionEndpoint              string `json:"introspection_endpoint"`
	OpenidProvidersEndpoint            string `json:"openid_providers_endpoint"`
	NonceEndpoint                      string `json:"nonce_endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
}

// pdpBackend is a confidential client of the PDP: it drives the auth-code flow, holds DPoP-bound tokens
// server-side (keyed by AS issuer on the session), and injects them into the gated /api reverse-proxy.
type pdpBackend struct {
	cfg       PDPConfig
	meta      asMetadata
	http      *http.Client
	signer    sessionSigner
	providers []Provider // the AS's IdP list, cached at construction (the chooser + single-provider default)
}

// NewPDPBackend discovers the AS metadata and returns the backend (a confidential BFF client of the PDP).
func NewPDPBackend(cfg PDPConfig) (Backend, error) {
	if cfg.ASIssuer == "" || cfg.ClientID == "" || cfg.SigningKey == nil {
		return nil, errors.New("pdp backend: as_issuer, client_id, signing key required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	b := &pdpBackend{cfg: cfg, http: hc, signer: sessionKeySigner{}}
	meta, err := b.discoverMetadata(cfg.ASIssuer)
	if err != nil {
		return nil, fmt.Errorf("pdp discovery: %w", err)
	}
	b.meta = meta
	// Cache the AS's provider list once: pep treats it exactly like the provider backend's static list — a
	// single provider auto-starts, several show the chooser. pep has no knowledge of which (if any) is a mock.
	if ps, err := b.fetchProviders(); err != nil {
		slog.Warn("pdp: fetch openid-providers failed", "error", err)
	} else {
		for _, p := range ps {
			b.providers = append(b.providers, Provider{Issuer: p.Issuer, Name: p.Name, LogoURI: p.LogoURI, Type: p.Type})
		}
	}
	return b, nil
}

// clientAssertion mints a private_key_jwt (RFC 7523 §2.2): iss=sub=client_id, aud=the AS's real issuer, a
// fresh AS nonce, and cnf.jkt = the SESSION DPoP-key thumbprint, binding the token to the per-session key.
func (b *pdpBackend) clientAssertion(ctx context.Context, sess *Session) (string, error) {
	if b.cfg.SigningKey == nil {
		return "", errors.New("client signing key not configured")
	}
	dkey, err := parseSessionDPoPKey(sess.DPoPKeyJWK)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := map[string]any{
		"iss": b.cfg.ClientID,
		"sub": b.cfg.ClientID,
		// An array, not a string: the PDP's client_assertion decoder takes aud as a list.
		"aud": []string{b.meta.Issuer},
		"jti": uuid.NewV4().String(),
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"cnf": map[string]string{"jkt": dkey.Thumbprint()},
	}
	if b.meta.NonceEndpoint != "" {
		nonce, err := b.fetchNonce(ctx)
		if err != nil {
			return "", fmt.Errorf("fetch nonce: %w", err)
		}
		claims["nonce"] = nonce
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode client_assertion claims: %w", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: b.cfg.SigningKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("client_assertion signer: %w", err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign client_assertion: %w", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("sign client_assertion: %w", err)
	}
	return compact, nil
}

// fetchNonce gets a one-time nonce from the AS nonce endpoint (plain-text body). Port of bff fetchNonce.
func (b *pdpBackend) fetchNonce(ctx context.Context) (string, error) {
	if b.meta.NonceEndpoint == "" {
		return "", errors.New("no nonce_endpoint in metadata")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.meta.NonceEndpoint, nil) //nolint:gosec // the URL is an endpoint from the metadata of the operator-configured AS; nothing from the request selects the host
	if err != nil {
		return "", err
	}
	resp, err := b.http.Do(req) //nolint:gosec // the URL is an endpoint from the metadata of the operator-configured AS; nothing from the request selects the host
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("nonce endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// discoverMetadata fetches the RFC 8414 authorization-server metadata document. Port of bff discoverMetadata.
func (b *pdpBackend) discoverMetadata(issuer string) (asMetadata, error) {
	var md asMetadata
	u := strings.TrimRight(issuer, "/") + "/.well-known/oauth-authorization-server"
	resp, err := b.http.Get(u)
	if err != nil {
		return md, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return md, fmt.Errorf("metadata endpoint %s returned %d", u, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		return md, fmt.Errorf("decode metadata: %w", err)
	}
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" {
		return md, errors.New("metadata missing authorization/token endpoint")
	}
	return md, nil
}

// DefaultIssuer auto-starts a single provider (like the provider backend); several show the chooser.
func (b *pdpBackend) DefaultIssuer() string {
	if len(b.providers) == 1 {
		return b.providers[0].Issuer
	}
	return ""
}

type providerInfo struct {
	Issuer  string `json:"iss"`
	LogoURI string `json:"logo_uri"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

func (b *pdpBackend) Providers(_ context.Context) ([]Provider, error) {
	return b.providers, nil
}

func (b *pdpBackend) fetchProviders() ([]providerInfo, error) {
	if b.meta.OpenidProvidersEndpoint == "" {
		return nil, errors.New("no openid_providers_endpoint in metadata")
	}
	resp, err := b.http.Get(b.meta.OpenidProvidersEndpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openid providers endpoint returned %d", resp.StatusCode)
	}
	var ps []providerInfo
	if err := json.NewDecoder(resp.Body).Decode(&ps); err != nil {
		return nil, err
	}
	return ps, nil
}

func (b *pdpBackend) StartLogin(ctx context.Context, sess *Session, idpIss, scope string) (LoginStart, error) {
	_, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		return LoginStart{}, err
	}
	sess.DPoPKeyJWK = jwkJSON
	sess.State = uuid.NewV4().String()
	sess.Nonce = uuid.NewV4().String()
	sess.CodeVerifier = oauth.GenerateVerifier()
	sess.CodeChallengeMethod = oauth.CodeChallengeMethodS256
	if scope == "" {
		scope = strings.Join(b.cfg.Scopes, " ")
	}
	sess.IDPIss = idpIss

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {b.cfg.ClientID},
		"redirect_uri":          {b.cfg.RedirectURI},
		"state":                 {sess.State},
		"nonce":                 {sess.Nonce},
		"scope":                 {scope},
		"code_challenge":        {oauth.S256Challenge(sess.CodeVerifier)},
		"code_challenge_method": {oauth.CodeChallengeMethodS256},
	}
	if idpIss != "" {
		params.Set("idp_iss", idpIss)
	}

	// Prefer PAR (RFC 9126 / FAPI 2.0): push the request back-channel (client-authenticated), then send the
	// browser to /authorize with only client_id + the single-use request_uri. Fall back to the direct URL
	// when the AS doesn't advertise a PAR endpoint.
	var authURL string
	if b.meta.PushedAuthorizationRequestEndpoint != "" {
		requestURI, err := b.pushAuthorizationRequest(ctx, sess, params)
		if err != nil {
			return LoginStart{}, fmt.Errorf("PAR: %w", err)
		}
		authURL = b.meta.AuthorizationEndpoint + "?" + url.Values{
			"client_id":   {b.cfg.ClientID},
			"request_uri": {requestURI},
		}.Encode()
	} else {
		authURL = b.meta.AuthorizationEndpoint + "?" + params.Encode()
	}

	mode := "redirect"
	for _, p := range b.providers {
		if p.Issuer == idpIss && p.Type == "oidf" {
			mode = "decoupled"
			break
		}
	}
	if mode == "decoupled" {
		directURL, err := b.resolveDecoupledAuthURL(authURL)
		if err != nil {
			return LoginStart{}, fmt.Errorf("start decoupled login: %w", err)
		}
		authURL = directURL
	}
	return LoginStart{AuthURL: authURL, Mode: mode}, nil
}

// pushAuthorizationRequest sends the authorization parameters to the AS's PAR endpoint (RFC 9126),
// client-authenticated by private_key_jwt, and returns the single-use request_uri.
func (b *pdpBackend) pushAuthorizationRequest(ctx context.Context, sess *Session, params url.Values) (string, error) {
	assertion, err := b.clientAssertion(ctx, sess)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	maps.Copy(form, params)
	form.Set("client_assertion_type", oauth.ClientAssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.meta.PushedAuthorizationRequestEndpoint, strings.NewReader(form.Encode())) //nolint:gosec // the URL is an endpoint from the metadata of the operator-configured AS; nothing from the request selects the host
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.http.Do(req) //nolint:gosec // the URL is an endpoint from the metadata of the operator-configured AS; nothing from the request selects the host
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("PAR endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	var pr struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(body, &pr); err != nil {
		return "", fmt.Errorf("decode PAR response: %w", err)
	}
	if pr.RequestURI == "" {
		return "", errors.New("PAR response missing request_uri")
	}
	return pr.RequestURI, nil
}

// resolveDecoupledAuthURL drives the AS authorization request server-side (the AS performs the PAR) without
// following the redirect, returning the provider authorization URL from the 3xx Location. Port of bff.
func (b *pdpBackend) resolveDecoupledAuthURL(authURL string) (string, error) {
	noRedirect := *b.http
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Get(authURL) //nolint:gosec // authURL is the AS's authorization endpoint from its metadata; the request only contributes url-encoded query values
	if err != nil {
		return "", fmt.Errorf("fetch authorization url: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("authorization server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	loc, err := resp.Location()
	if err != nil {
		return "", fmt.Errorf("authorization redirect without Location: %w", err)
	}
	if e := loc.Query().Get("error"); e != "" {
		return "", fmt.Errorf("%s: %s", e, loc.Query().Get("error_description"))
	}
	return loc.String(), nil
}

func (b *pdpBackend) Complete(ctx context.Context, sess *Session, code string) error {
	tr, err := b.tokenRequest(ctx, sess, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {sess.CodeVerifier},
		"redirect_uri":  {b.cfg.RedirectURI},
	})
	if err != nil {
		return fmt.Errorf("exchange code: %w", err)
	}
	b.storeTokens(sess, tr)
	// Best effort: introspect for the upstream identity (the forward_auth headers come from sess.Identity).
	if identity, err := b.introspectIdentity(ctx, sess, tr.AccessToken); err != nil {
		slog.Warn("pdp introspection failed", "error", err)
	} else {
		sess.Identity = identity
	}
	return nil
}

func (b *pdpBackend) FreshAccessToken(ctx context.Context, sess *Session) (string, error) {
	e, ok := sess.GetTokens(b.cfg.ASIssuer)
	if !ok {
		return "", fmt.Errorf("no token for %s", b.cfg.ASIssuer)
	}
	if e.ExpiresAt.IsZero() || time.Until(e.ExpiresAt) > 30*time.Second || e.RefreshToken == "" {
		return e.AccessToken, nil
	}
	tr, err := b.tokenRequest(ctx, sess, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {e.RefreshToken},
	})
	if err != nil {
		return "", err
	}
	b.storeTokens(sess, tr)
	return tr.AccessToken, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (b *pdpBackend) storeTokens(sess *Session, tr *tokenResponse) {
	var exp time.Time
	if tr.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	sess.SetTokens(b.cfg.ASIssuer, &TokenEntry{AccessToken: tr.AccessToken, RefreshToken: tr.RefreshToken, ExpiresAt: exp})
}

// tokenRequest posts to the AS token endpoint authenticated by private_key_jwt and BOUND by a DPoP proof on
// the request itself (RFC 9449): the proof (signed with the session DPoP key, no ath) is what makes the AS
// issue a sender-constrained token. Retries once on a DPoP-Nonce challenge.
func (b *pdpBackend) tokenRequest(ctx context.Context, sess *Session, form url.Values) (*tokenResponse, error) {
	assertion, err := b.clientAssertion(ctx, sess)
	if err != nil {
		return nil, err
	}
	form.Set("client_id", b.cfg.ClientID)
	form.Set("client_assertion_type", oauth.ClientAssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)

	do := func(nonce string) (*http.Response, error) {
		proof, err := b.tokenDPoPProof(sess, nonce)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.meta.TokenEndpoint, strings.NewReader(form.Encode())) //nolint:gosec // the URL is an endpoint from the metadata of the operator-configured AS; nothing from the request selects the host
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(dpop.HeaderName, proof)
		return b.http.Do(req) //nolint:gosec // the URL is an endpoint from the metadata of the operator-configured AS; nothing from the request selects the host
	}

	resp, err := do("")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusBadRequest {
		if n := resp.Header.Get("DPoP-Nonce"); n != "" {
			_ = resp.Body.Close()
			if resp, err = do(n); err != nil {
				return nil, err
			}
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("token endpoint %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// tokenDPoPProof signs a DPoP proof for the token endpoint (htm=POST, htu=token endpoint, no ath — there is
// no access token to bind yet) with the session DPoP key. A server-supplied nonce is included when present.
func (b *pdpBackend) tokenDPoPProof(sess *Session, nonce string) (string, error) {
	key, err := parseSessionDPoPKey(sess.DPoPKeyJWK)
	if err != nil {
		return "", err
	}
	return key.Proof(http.MethodPost, b.meta.TokenEndpoint, dpop.ProofOptions{Nonce: nonce})
}

// introspectIdentity introspects the access token at the AS (RFC 7662) for the upstream identity, surfacing
// the nested identity claims.
func (b *pdpBackend) introspectIdentity(ctx context.Context, sess *Session, accessToken string) (map[string]any, error) {
	if b.meta.IntrospectionEndpoint == "" {
		return nil, errors.New("no introspection_endpoint in metadata")
	}
	assertion, err := b.clientAssertion(ctx, sess)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"token":                 {accessToken},
		"client_assertion_type": {oauth.ClientAssertionTypeJWTBearer},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.meta.IntrospectionEndpoint, strings.NewReader(form.Encode())) //nolint:gosec // the URL is an endpoint from the metadata of the operator-configured AS; nothing from the request selects the host
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.http.Do(req) //nolint:gosec // the URL is an endpoint from the metadata of the operator-configured AS; nothing from the request selects the host
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection returned %d", resp.StatusCode)
	}
	var ir map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return nil, err
	}
	if active, _ := ir["active"].(bool); !active {
		return nil, errors.New("token is not active")
	}
	if claims, ok := ir["identity"].(map[string]any); ok {
		return claims, nil
	}
	return ir, nil
}
