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

// Package pep is a policy enforcement point for HTTP resources: Enforcers decide on each request from its
// access token, DPoP proof or session cookie, and a denial becomes an OAuth 2.0 error response.
package pep

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gematik/zero-lab/go/dpop"
)

const defaultHTTPTimeout = 30 * time.Second

// PEP holds what the enforcers verify requests against: the JWK set, the protected resource and its public
// origin. It is made by a Builder.
type PEP struct {
	slogger                   *slog.Logger
	httpClient                *http.Client
	provideJwkSetFunc         func() (jwk.Set, error)
	decryptAccessTokenFunc    func(string) (string, error)
	accessTokenAcceptableSkew time.Duration
	resource                  string // URI of the resource being protected
	// publicOrigin is the scheme, host and port clients reach the protected resource at; the
	// DPoP proof's htu is checked against it plus the request path (RFC 9449 Section 4.3).
	publicOrigin string
	dpopVerifier *dpop.Verifier
}

// Builder configures a PEP. An option that fails records its error for Build to return.
type Builder struct {
	p   *PEP
	err error
}

// NewBuilder starts a Builder with no JWK set source, which Build requires.
func NewBuilder() *Builder {
	return &Builder{p: &PEP{}}
}

// Build returns the PEP or the recorded error. It fails without a JWK set source or with a public origin
// that is not an absolute http or https URL. Defaults: a 30 s HTTP client, the default slog logger, one
// minute of skew, and the resource's origin as public origin.
func (b *Builder) Build() (*PEP, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.p.provideJwkSetFunc == nil {
		return nil, errors.New("none of the JWKSet provider has been set")
	}
	if b.p.httpClient == nil {
		b.p.httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if b.p.slogger == nil {
		b.p.slogger = slog.Default()
	}
	if b.p.accessTokenAcceptableSkew == 0 {
		b.p.accessTokenAcceptableSkew = 1 * time.Minute
	}
	if b.p.publicOrigin == "" && b.p.resource != "" {
		b.p.publicOrigin = b.p.resource
	}
	if b.p.publicOrigin != "" {
		origin, err := originOf(b.p.publicOrigin)
		if err != nil {
			return nil, fmt.Errorf("public origin %q: %w", b.p.publicOrigin, err)
		}
		b.p.publicOrigin = origin
	}
	// Replay detection covers this process only (RFC 9449 Section 11.1).
	verifier, err := dpop.NewVerifier(dpop.Config{Replay: dpop.NewMemoryReplayCache(100_000, nil)})
	if err != nil {
		return nil, fmt.Errorf("dpop verifier: %w", err)
	}
	b.p.dpopVerifier = verifier
	return b.p, nil
}

// originOf is the scheme://host[:port] of an absolute http(s) URL.
func originOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("not an absolute http or https URL")
	}
	return u.Scheme + "://" + u.Host, nil
}

// WithJWKSetFunc sets the source of the verification keys; f is called for every token, so it can follow
// key rotation and should cache.
func (b *Builder) WithJWKSetFunc(f func() (jwk.Set, error)) *Builder {
	b.p.provideJwkSetFunc = f
	return b
}

// WithJWKSet sets a fixed set of verification keys.
func (b *Builder) WithJWKSet(jwkSet jwk.Set) *Builder {
	b.p.provideJwkSetFunc = func() (jwk.Set, error) {
		return jwkSet, nil
	}
	return b
}

// WithJWKSetPath reads a fixed set of verification keys from a file, once and at this call.
func (b *Builder) WithJWKSetPath(path string) *Builder {
	data, err := os.ReadFile(path)
	if err != nil {
		b.err = fmt.Errorf("could not read JWKSet from %s: %w", path, err)
	}
	jwks, err := jwk.Parse(data)
	if err != nil {
		b.err = fmt.Errorf("could not parse JWKSet from %s: %w", path, err)
	}

	return b.WithJWKSet(jwks)
}

// WithAccessTokenAcceptableSkew sets the clock skew tolerated on a token's time claims; zero means one minute.
func (b *Builder) WithAccessTokenAcceptableSkew(d time.Duration) *Builder {
	b.p.accessTokenAcceptableSkew = d
	return b
}

// WithDecryptAccessTokenFunc stores a decrypter for encrypted access tokens. Verification does not call it
// yet, so an encrypted token is still refused.
func (b *Builder) WithDecryptAccessTokenFunc(f func(string) (string, error)) *Builder {
	b.p.decryptAccessTokenFunc = f
	return b
}

// WithHTTPClient sets the client for outbound requests. Verification makes none yet.
func (b *Builder) WithHTTPClient(client *http.Client) *Builder {
	b.p.httpClient = client
	return b
}

// WithSlogger sets the logger of the PEP and of the contexts it creates.
func (b *Builder) WithSlogger(slogger *slog.Logger) *Builder {
	b.p.slogger = slogger
	return b
}

// Resource sets the URI of the protected resource: a token's audience must match it, and it is the default
// public origin. Without it the audience is not restricted.
func (b *Builder) Resource(resource string) *Builder {
	b.p.resource = resource
	return b
}

// PublicOrigin sets the scheme, host and port clients reach the protected resource at, for the
// DPoP htu check. Without it, the resource's origin is used.
func (b *Builder) PublicOrigin(origin string) *Builder {
	b.p.publicOrigin = origin
	return b
}

// Close releases the resources of the PEP. It holds none yet, so it always returns nil.
func (p *PEP) Close() error {
	// TODO: reserved for future use
	return nil
}

func (p *PEP) deny(ctx Context, err Error) {
	w := ctx.Writer()
	r := ctx.Request()
	slog.Debug("Request denied", "method", r.Method, "url", r.URL)
	if err.WWWAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", err.WWWAuthenticate)
	}
	// A request without credentials gets the challenge alone: no error code, so no error body
	// (RFC 6750 Section 3.1, RFC 9449 Figure 15).
	if err.Code == "" {
		w.WriteHeader(err.HTTPStatus)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus)
	if encErr := json.NewEncoder(w).Encode(err); encErr != nil {
		slog.Warn("Could not write denial", "error", encErr)
	}
}

// HandlerFunc continues a request an Enforcer let through.
type HandlerFunc func(ctx Context)

// Context is one request as an Enforcer sees it.
type Context interface {
	Writer() http.ResponseWriter
	Request() *http.Request
	Deny(err Error)
	WithDeny(deny func(c Context, err Error)) Context
	Slogger() *slog.Logger
	UnmarshalClaims(claims any) error
	// SetClaims sets the raw JSON claims that UnmarshalClaims reads. A token-verifying enforcer sets these
	// from the verified token; a session-cookie enforcer sets them from the cookie identity.
	SetClaims(raw []byte)
}

type pepContext struct {
	pep            *PEP
	slogger        *slog.Logger
	writer         http.ResponseWriter
	request        *http.Request
	deny           func(Context, Error)
	accessTokenRaw string
	accessToken    jwt.Token
	dpop           *dpop.Proof
	claimsRaw      []byte
}

func (c *pepContext) Writer() http.ResponseWriter {
	return c.writer
}

func (c *pepContext) Request() *http.Request {
	return c.request
}

func (c *pepContext) Deny(err Error) {
	c.deny(c, err)
}

func (c *pepContext) WithDeny(deny func(Context, Error)) Context {
	return &pepContext{
		pep:     c.pep,
		slogger: c.slogger,
		writer:  c.writer,
		request: c.request,
		deny:    deny,
	}
}

func (c *pepContext) Slogger() *slog.Logger {
	return c.slogger
}

func (c *pepContext) SetClaims(raw []byte) {
	c.claimsRaw = raw
}

func (c *pepContext) UnmarshalClaims(claims any) error {
	if c.claimsRaw == nil {
		return errors.New("claims not available, authorize_bearer or dpop not used")
	}
	if err := json.Unmarshal(c.claimsRaw, claims); err != nil {
		return fmt.Errorf("unable to unmarshal claims: %w", err)
	}

	return nil
}

func (c *pepContext) verifyAuthorizationBearer() error {
	bearerToken, err := c.parseAuthorizationScheme("bearer")
	if err != nil {
		return err
	}
	return c.verifyAccessToken(bearerToken)
}

// verifyAuthorizationDPoP checks a DPoP-bound access token and its proof (RFC 9449 Section 7.1):
// the DPoP-scheme credentials, the access token, and the proof for this request's method and URI,
// with ath and the key binding to the token's cnf.jkt. The URI is the configured public origin
// plus the request path, never one built from the client's Host or X-Forwarded-* headers.
func (c *pepContext) verifyAuthorizationDPoP() error {
	if c.pep.publicOrigin == "" {
		return errors.New("DPoP needs the resource's public origin: set PublicOrigin or Resource")
	}
	accessToken, err := dpop.AccessToken(c.request.Header)
	if err != nil {
		return err
	}
	if err := c.verifyAccessToken(accessToken); err != nil {
		return err
	}
	// An unbound token has no cnf.jkt; the verifier refuses it as invalid_token.
	var jkt string
	var cnf map[string]any
	if c.accessToken.Get("cnf", &cnf) == nil {
		jkt, _ = cnf["jkt"].(string)
	}
	proof, err := c.pep.dpopVerifier.Verify(c.request.Header, dpop.Request{
		Method:      c.request.Method,
		URI:         c.pep.publicOrigin + c.request.URL.EscapedPath(),
		AccessToken: accessToken,
		Thumbprint:  jkt,
	})
	if err != nil {
		return err
	}
	c.dpop = proof
	return nil
}

// dpopDenial is the pep Error for a DPoP refusal: the status RFC 6750 Section 3.1 gives the
// code, and the challenge of RFC 9449 Section 7.1.
func (p *PEP) dpopDenial(e *dpop.Error) Error {
	status := http.StatusUnauthorized
	if e.Code == dpop.CodeInvalidRequest {
		status = http.StatusBadRequest
	}
	return Error{
		HTTPStatus:      status,
		Code:            e.Code,
		Description:     e.Description,
		WWWAuthenticate: p.dpopVerifier.Challenge(e),
	}
}

func (c *pepContext) parseAuthorizationScheme(scheme string) (string, error) {
	authzHeaders := c.request.Header.Values("Authorization")
	if len(authzHeaders) == 0 {
		return "", ErrNoAuthorizationHeader
	}
	for _, authzHeader := range authzHeaders {
		parts := strings.Split(authzHeader, " ")
		if len(parts) != 2 {
			continue
		}

		authScheme := strings.ToLower(parts[0])
		if authScheme == scheme {
			return parts[1], nil
		}
	}

	return "", ErrInvalidAuthorizationHeader
}

func (c *pepContext) verifyAccessToken(accessToken string) error {
	jwtToken, err := c.pep.VerifyAccessToken(accessToken)
	if err != nil {
		return &Error{
			HTTPStatus:  http.StatusUnauthorized,
			Code:        "invalid_token",
			Description: fmt.Sprintf("invalid access token: %s", err),
		}
	}
	c.accessTokenRaw = accessToken
	c.accessToken = jwtToken

	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWT format")
	}

	claimsSegment := parts[1]
	claimsRaw, err := base64.RawURLEncoding.DecodeString(claimsSegment)
	if err != nil {
		return fmt.Errorf("invalid JWT claims segment: %w", err)
	}

	c.claimsRaw = claimsRaw

	return nil
}

// NewContext returns the Context of one request; its Deny writes the error response to w.
func (p *PEP) NewContext(w http.ResponseWriter, r *http.Request) Context {
	return &pepContext{
		pep:     p,
		slogger: p.slogger,
		writer:  w,
		request: r,
		deny:    p.deny,
	}
}

// GuardedHandlerFunc wraps next so that it only runs when enforcer lets the request through; a denial writes
// the error response instead.
func (p *PEP) GuardedHandlerFunc(enforcer Enforcer, next func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := p.NewContext(w, r)
		enforcer.Apply(ctx, func(ctx Context) {
			next(ctx.Writer(), ctx.Request())
		})
	}
}

// VerifyAccessToken parses and verifies a JWT access token against the configured JWKSet. When a
// resource is set (guarding a resource server) the token's audience must match it; with no resource
// configured — e.g. when an authorization server reuses the PEP to verify its own tokens — the
// audience is not restricted.
func (p *PEP) VerifyAccessToken(tokenRaw string) (jwt.Token, error) {
	jwks, err := p.provideJwkSetFunc()
	if err != nil {
		return nil, fmt.Errorf("could not get JWKSet: %w", err)
	}
	opts := []jwt.ParseOption{
		jwt.WithAcceptableSkew(p.accessTokenAcceptableSkew),
		jwt.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)),
	}
	if p.resource != "" {
		opts = append(opts, jwt.WithAudience(p.resource))
	}
	token, err := jwt.ParseString(tokenRaw, opts...)
	if err != nil {
		p.slogger.Warn("could not parse JWT", "error", err)
		return nil, fmt.Errorf("could not parse JWT: %w", err)
	}

	return token, nil
}
