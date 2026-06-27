package proxy

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/segmentio/ksuid"
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
