package proxy

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/segmentio/ksuid"
	"golang.org/x/oauth2"
)

const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// PDPConfig configures the pdpBackend: pep as a confidential OAuth client of the PDP (the gematik AS).
type PDPConfig struct {
	ASIssuer    string  // the PDP authorization server (login + identity)
	ClientID    string  // pep's registered client_id
	SigningKey  jwk.Key // private_key_jwt signing key (loaded from a *_PATH file)
	RedirectURI string  // default <public>/oauth2/callback
	Scopes      []string
	APIPrefix   string // gated reverse-proxy prefix, default /api
	APIUpstream string // the single allowlisted upstream for that prefix
	HTTPClient  *http.Client
}

// asMetadata is the subset of RFC 8414 authorization-server metadata the backend needs.
type asMetadata struct {
	Issuer                  string `json:"issuer"`
	AuthorizationEndpoint   string `json:"authorization_endpoint"`
	TokenEndpoint           string `json:"token_endpoint"`
	IntrospectionEndpoint   string `json:"introspection_endpoint"`
	OpenidProvidersEndpoint string `json:"openid_providers_endpoint"`
	NonceEndpoint           string `json:"nonce_endpoint"`
}

// pdpBackend is a confidential BFF client of the PDP: it drives the auth-code flow, holds DPoP-bound tokens
// server-side (keyed by AS issuer on the session), and injects them into the gated /api reverse-proxy.
type pdpBackend struct {
	cfg    PDPConfig
	meta   asMetadata
	http   *http.Client
	signer sessionSigner
}

// NewPDPBackend discovers the AS metadata and returns the backend. (Returns the concrete type until the
// remaining Backend methods land; callers assign it to proxy.Config.Backend.)
func NewPDPBackend(cfg PDPConfig) (*pdpBackend, error) {
	if cfg.ASIssuer == "" || cfg.ClientID == "" || cfg.SigningKey == nil {
		return nil, fmt.Errorf("pdp backend: as_issuer, client_id, signing key required")
	}
	if cfg.APIPrefix == "" {
		cfg.APIPrefix = "/api"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	b := &pdpBackend{cfg: cfg, http: hc, signer: bffSigner{}}
	meta, err := b.discoverMetadata(cfg.ASIssuer)
	if err != nil {
		return nil, fmt.Errorf("pdp discovery: %w", err)
	}
	b.meta = meta
	return b, nil
}

// clientAssertion mints a private_key_jwt (RFC 7523 §2.2): iss=sub=client_id, aud=the AS's real issuer, a
// fresh AS nonce, and cnf.jkt = the SESSION DPoP-key thumbprint. Port of bff clientAssertion, adapted to
// bind the token to the per-session key.
func (b *pdpBackend) clientAssertion(ctx context.Context, sess *Session) (string, error) {
	if b.cfg.SigningKey == nil {
		return "", fmt.Errorf("client signing key not configured")
	}
	dkey, err := parseSessionDPoPKey(sess.DPoPKeyJWK)
	if err != nil {
		return "", fmt.Errorf("session dpop key: %w", err)
	}
	thumb, err := dkey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop thumbprint: %w", err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)

	now := time.Now()
	tok := jwt.New()
	tok.Set(jwt.IssuerKey, b.cfg.ClientID)
	tok.Set(jwt.SubjectKey, b.cfg.ClientID)
	tok.Set(jwt.AudienceKey, b.meta.Issuer)
	tok.Set(jwt.JwtIDKey, ksuid.New().String())
	tok.Set(jwt.IssuedAtKey, now.Unix())
	tok.Set(jwt.ExpirationKey, now.Add(time.Minute).Unix())
	tok.Set("cnf", map[string]string{"jkt": jkt})
	if b.meta.NonceEndpoint != "" {
		nonce, err := b.fetchNonce(ctx)
		if err != nil {
			return "", fmt.Errorf("fetch nonce: %w", err)
		}
		tok.Set("nonce", nonce)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), b.cfg.SigningKey))
	if err != nil {
		return "", fmt.Errorf("sign client_assertion: %w", err)
	}
	return string(signed), nil
}

// fetchNonce gets a one-time nonce from the AS nonce endpoint (plain-text body). Port of bff fetchNonce.
func (b *pdpBackend) fetchNonce(ctx context.Context) (string, error) {
	if b.meta.NonceEndpoint == "" {
		return "", fmt.Errorf("no nonce_endpoint in metadata")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.meta.NonceEndpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := b.http.Do(req)
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
		return md, fmt.Errorf("metadata missing authorization/token endpoint")
	}
	return md, nil
}

// DefaultIssuer returns the AS issuer as a "let the PDP pick the IdP" sentinel, so login auto-starts (the
// PDP applies its own default_idp_iss) instead of showing the chooser. StartLogin normalizes it to no idp_iss.
func (b *pdpBackend) DefaultIssuer() string { return b.cfg.ASIssuer }

type providerInfo struct {
	Issuer  string `json:"iss"`
	LogoURI string `json:"logo_uri"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

func (b *pdpBackend) Providers(ctx context.Context) ([]Provider, error) {
	ps, err := b.fetchProviders()
	if err != nil {
		return nil, err
	}
	out := make([]Provider, 0, len(ps))
	for _, p := range ps {
		out = append(out, Provider{Issuer: p.Issuer, Name: p.Name, LogoURI: p.LogoURI, Type: p.Type})
	}
	return out, nil
}

func (b *pdpBackend) fetchProviders() ([]providerInfo, error) {
	if b.meta.OpenidProvidersEndpoint == "" {
		return nil, fmt.Errorf("no openid_providers_endpoint in metadata")
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

func (b *pdpBackend) lookupProvider(issuer string) (*providerInfo, error) {
	ps, err := b.fetchProviders()
	if err != nil {
		return nil, err
	}
	for i := range ps {
		if ps[i].Issuer == issuer {
			return &ps[i], nil
		}
	}
	return nil, fmt.Errorf("provider %q not found", issuer)
}

func (b *pdpBackend) StartLogin(ctx context.Context, sess *Session, idpIss, scope string) (LoginStart, error) {
	_, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		return LoginStart{}, err
	}
	sess.DPoPKeyJWK = jwkJSON
	sess.State = ksuid.New().String()
	sess.Nonce = ksuid.New().String()
	sess.CodeVerifier = oauth2.GenerateVerifier()
	sess.CodeChallengeMethod = "S256"
	if scope == "" {
		scope = strings.Join(b.cfg.Scopes, " ")
	}
	if idpIss == b.cfg.ASIssuer { // the DefaultIssuer sentinel → let the PDP decide
		idpIss = ""
	}
	sess.IDPIss = idpIss

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {b.cfg.ClientID},
		"redirect_uri":          {b.cfg.RedirectURI},
		"state":                 {sess.State},
		"nonce":                 {sess.Nonce},
		"scope":                 {scope},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(sess.CodeVerifier)},
		"code_challenge_method": {"S256"},
	}
	if idpIss != "" {
		params.Set("idp_iss", idpIss)
	}
	authURL := b.meta.AuthorizationEndpoint + "?" + params.Encode()

	mode := "redirect"
	if idpIss != "" {
		if p, err := b.lookupProvider(idpIss); err == nil && p != nil && p.Type == "oidf" {
			mode = "decoupled"
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

// resolveDecoupledAuthURL drives the AS authorization request server-side (the AS performs the PAR) without
// following the redirect, returning the provider authorization URL from the 3xx Location. Port of bff.
func (b *pdpBackend) resolveDecoupledAuthURL(authURL string) (string, error) {
	noRedirect := *b.http
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Get(authURL)
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
	form.Set("client_assertion_type", clientAssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)

	do := func(nonce string) (*http.Response, error) {
		proof, err := b.tokenDPoPProof(sess, nonce)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.meta.TokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(dpop.DPoPHeaderName, proof)
		return b.http.Do(req)
	}

	resp, err := do("")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusBadRequest {
		if n := resp.Header.Get("DPoP-Nonce"); n != "" {
			resp.Body.Close()
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
	pk, err := dpop.FromJWK(key)
	if err != nil {
		return "", err
	}
	bld := dpop.NewBuilder().HttpMethod(http.MethodPost).HttpURI(b.meta.TokenEndpoint)
	if nonce != "" {
		bld = bld.Nonce(nonce)
	}
	tok, err := bld.Build()
	if err != nil {
		return "", err
	}
	return tok.Sign(pk)
}

// introspectIdentity introspects the access token at the AS (RFC 7662) for the upstream identity, surfacing
// the nested identity claims. Port of bff introspectIdentity, adapted to take the session for the assertion.
func (b *pdpBackend) introspectIdentity(ctx context.Context, sess *Session, accessToken string) (map[string]any, error) {
	if b.meta.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("no introspection_endpoint in metadata")
	}
	assertion, err := b.clientAssertion(ctx, sess)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"token":                 {accessToken},
		"client_assertion_type": {clientAssertionTypeJWTBearer},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.meta.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.http.Do(req)
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
		return nil, fmt.Errorf("token is not active")
	}
	if claims, ok := ir["identity"].(map[string]any); ok {
		return claims, nil
	}
	return ir, nil
}
