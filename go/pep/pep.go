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
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
)

const defaultHTTPTimeout = 30 * time.Second

// PEP holds what the enforcers verify requests against: the JWK set, the protected resource and its public
// origin. It is made by a Builder.
type PEP struct {
	slogger           *slog.Logger
	httpClient        *http.Client
	provideJwkSetFunc func() (*jose.JSONWebKeySet, error)
	// keySource is asked again when a token names a kid the set does not hold; nil for a fixed set.
	keySource                 KeySource
	decryptAccessTokenFunc    func(string) (string, error)
	accessTokenAcceptableSkew time.Duration
	resource                  string // URI of the resource being protected
	// resourceMetadataURL is where the resource's metadata is (RFC 9728 Section 3.1); every 401 challenge names it.
	resourceMetadataURL string
	// acceptUntyped takes an access token whose typ is not at+jwt, for an authorization server known to omit it.
	acceptUntyped bool
	// publicOrigin is the scheme, host and port clients reach the protected resource at; the
	// DPoP proof's htu is checked against it plus the request path (RFC 9449 Section 4.3).
	publicOrigin string
	dpopVerifier *dpop.Verifier
	// dpopNonceVerifier checks proofs for the enforcers that require a nonce; nil without a nonce source.
	dpopNonceVerifier *dpop.Verifier
	dpopNonces        dpop.NonceSource
	// sessionRevocations are what EnforcerSessionCookie asks whether a snapshot's session was ended; nil denies.
	sessionRevocations SessionRevocations
	// now is the time tokens, proofs and cookies are judged at.
	now func() time.Time
}

// Builder configures a PEP. An option that fails records its error for Build to return.
type Builder struct {
	p           *PEP
	err         error
	dpopReplays dpop.Replays
	dpopNonces  dpop.NonceSource
}

// NewBuilder starts a Builder with no JWK set source, which Build requires.
func NewBuilder() *Builder {
	return &Builder{p: &PEP{}}
}

// Build returns the PEP or the recorded error. It fails without a JWK set source or with a public origin
// that is not an absolute http or https URL. Defaults: a 30 s HTTP client, no logging, one
// minute of skew, the resource's origin as public origin, and the resource metadata URL RFC 9728 Section 3.1
// derives from the resource.
func (b *Builder) Build() (*PEP, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.p.provideJwkSetFunc == nil {
		return nil, errors.New("none of the JWKSet provider has been set")
	}
	// RFC 9700 Section 4.10.2: a resource server refuses a token not meant for it, which it can tell only by the
	// audience, so a PEP always has one.
	if b.p.resource == "" {
		return nil, errors.New("no resource: call Resource with the URI the access tokens' aud names (RFC 9700 Section 4.10.2)")
	}
	if b.p.resourceMetadataURL == "" {
		metadataURL, err := ProtectedResourceMetadataURL(b.p.resource)
		if err != nil {
			return nil, fmt.Errorf("resource metadata URL: %w", err)
		}
		b.p.resourceMetadataURL = metadataURL
	} else if err := checkMetadataURL(b.p.resourceMetadataURL); err != nil {
		return nil, fmt.Errorf("resource metadata URL: %w", err)
	}
	if b.p.httpClient == nil {
		b.p.httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if b.p.slogger == nil {
		b.p.slogger = slog.New(slog.DiscardHandler)
	}
	if b.p.now == nil {
		b.p.now = time.Now
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
	// Where accepted proofs are remembered decides whether replicas see each other's (RFC 9449 Section 11.1):
	// the host's choice, never a default of this package.
	if b.dpopReplays == nil {
		return nil, errors.New("no DPoP replays: call WithDPoPReplays, with dpop.NewMemoryReplays for a single replica")
	}
	verifier, err := dpop.NewVerifier(dpop.Config{Replays: b.dpopReplays, Clock: clockFunc(b.p.now)})
	if err != nil {
		return nil, fmt.Errorf("dpop verifier: %w", err)
	}
	b.p.dpopVerifier = verifier
	if b.dpopNonces != nil {
		nonced, err := dpop.NewVerifier(dpop.Config{Replays: b.dpopReplays, Nonces: b.dpopNonces, Clock: clockFunc(b.p.now)})
		if err != nil {
			return nil, fmt.Errorf("dpop verifier with nonces: %w", err)
		}
		b.p.dpopNonceVerifier, b.p.dpopNonces = nonced, b.dpopNonces
	}
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
func (b *Builder) WithJWKSetFunc(f func() (*jose.JSONWebKeySet, error)) *Builder {
	b.p.provideJwkSetFunc = f
	b.p.keySource = nil
	return b
}

// KeySource is a source of verification keys that follows the authorization server's key rotation: Keys is
// the set in force, called for every token, and Refresh fetches the set again, called once when a token names a
// kid the set in force does not hold. Refresh returns the set to verify with afterwards: a newly verified set, or
// the one in force when the source declines to fetch. The host bounds how often Refresh fetches, since a client
// chooses the kid; a failed fetch keeps the set in force.
type KeySource interface {
	Keys() (*jose.JSONWebKeySet, error)
	Refresh(ctx context.Context) (*jose.JSONWebKeySet, error)
}

// WithKeySource sets source as the source of the verification keys, replacing any other.
func (b *Builder) WithKeySource(source KeySource) *Builder {
	if source == nil {
		b.err = errors.New("no key source")
		return b
	}
	b.p.keySource = source
	b.p.provideJwkSetFunc = source.Keys
	return b
}

// WithJWKSet sets a fixed set of verification keys.
func (b *Builder) WithJWKSet(jwkSet *jose.JSONWebKeySet) *Builder {
	b.p.provideJwkSetFunc = func() (*jose.JSONWebKeySet, error) {
		return jwkSet, nil
	}
	b.p.keySource = nil
	return b
}

// WithJWKSetPath reads a fixed set of verification keys from a file, once and at this call.
func (b *Builder) WithJWKSetPath(path string) *Builder {
	data, err := os.ReadFile(path)
	if err != nil {
		b.err = fmt.Errorf("could not read JWKSet from %s: %w", path, err)
		return b
	}
	jwks, err := ParseJWKSet(data)
	if err != nil {
		b.err = fmt.Errorf("could not parse JWKSet from %s: %w", path, err)
		return b
	}

	return b.WithJWKSet(jwks)
}

// WithDPoPNonces sets where the resource server's nonces come from (RFC 9449 Section 9), for the
// authorization_dpop enforcers that require one. Replicas behind one origin need a source whose nonces
// all of them accept, such as a nonce.Source over keys they share.
func (b *Builder) WithDPoPNonces(source dpop.NonceSource) *Builder {
	b.dpopNonces = source
	return b
}

// WithDPoPReplays sets where accepted DPoP proofs are remembered. A host running several replicas supplies
// replays they share, so a proof replayed at another replica is refused (RFC 9449 Section 11.1); this package
// stays free of any store. An error from them refuses the proof. Build requires them; a single replica can use
// dpop.NewMemoryReplays.
func (b *Builder) WithDPoPReplays(replays dpop.Replays) *Builder {
	b.dpopReplays = replays
	return b
}

// WithSessionRevocations sets the revocations EnforcerSessionCookie checks every snapshot's session against. A
// PEP without them denies every request on the session cookie: a signed-out session's snapshot stays valid until
// it expires, and only the revocations tell.
func (b *Builder) WithSessionRevocations(revocations SessionRevocations) *Builder {
	b.p.sessionRevocations = revocations
	return b
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

// WithClock sets the time tokens, DPoP proofs and session cookies are judged at; the default is the
// system clock.
func (b *Builder) WithClock(now func() time.Time) *Builder {
	b.p.now = now
	return b
}

// clockFunc is a func() time.Time as a dpop.Clock.
type clockFunc func() time.Time

func (f clockFunc) Now() time.Time { return f() }

// WithSlogger sets the logger of the PEP and of the contexts it creates; without one, or with nil, nothing is
// logged.
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

// AcceptUntypedAccessTokens takes access tokens whose typ is not at+jwt (RFC 9068 Section 4), for an authorization
// server known to omit it. Without it such a token is refused, so that another JWT the same key signs, an ID token
// among them, is not taken for an access token.
func (b *Builder) AcceptUntypedAccessTokens() *Builder {
	b.p.acceptUntyped = true
	return b
}

// ResourceMetadataURL sets the URL of the resource's metadata that the resource_metadata parameter of every 401
// challenge names (RFC 9728 Section 5.1), for a deployment that serves it elsewhere than Section 3.1 derives
// from the resource. It must be an absolute http or https URL a quoted-string carries unescaped.
func (b *Builder) ResourceMetadataURL(metadataURL string) *Builder {
	b.p.resourceMetadataURL = metadataURL
	return b
}

// checkMetadataURL refuses a resource metadata URL that is not absolute http or https or does not fit a challenge.
func checkMetadataURL(raw string) error {
	if _, err := originOf(raw); err != nil {
		return err
	}
	return checkChallengeURL(raw)
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
	ctx.Slogger().Debug("Request denied", "method", r.Method, "path", r.URL.Path)
	challenge := err.WWWAuthenticate
	// RFC 9728 Section 5.1: a client that starts at the resource learns from the 401 where the metadata naming
	// the authorization server is. A 403 is about a token the client already has, so it does not.
	if err.HTTPStatus == http.StatusUnauthorized {
		challenge = withResourceMetadata(challenge, p.resourceMetadataURL)
	}
	if challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	if err.DPoPNonce != "" {
		handOutNonce(w, err.DPoPNonce)
	}
	// A request without credentials gets the challenge alone: no error code, so no error body
	// (RFC 6750 Section 3.1, RFC 9449 Figure 15).
	if err.Code == "" {
		w.WriteHeader(err.HTTPStatus)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus)
	if encErr := writeJSONLine(w, err); encErr != nil {
		ctx.Slogger().Warn("Could not write denial", "error", encErr)
	}
}

// writeJSONLine writes v as JSON and a newline, so the denial body stays the one clients know.
func writeJSONLine(w http.ResponseWriter, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(body, '\n'))
	return err
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
	// Now is the time the request is judged at.
	Now() time.Time
	UnmarshalClaims(claims any) error
	// SetClaims sets the raw JSON claims that UnmarshalClaims reads. A token-verifying enforcer sets these
	// from the verified token; a session-cookie enforcer sets them from the cookie identity.
	SetClaims(raw []byte)
	// SessionRevocations are the revocations EnforcerSessionCookie checks a snapshot's session against; nil
	// when there are none, and the enforcer denies.
	SessionRevocations() SessionRevocations
}

type pepContext struct {
	pep            *PEP
	slogger        *slog.Logger
	writer         http.ResponseWriter
	request        *http.Request
	deny           func(Context, Error)
	accessTokenRaw string
	accessToken    *AccessToken
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

func (c *pepContext) Now() time.Time { return c.pep.now() }

func (c *pepContext) SessionRevocations() SessionRevocations { return c.pep.sessionRevocations }

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
		return &reasonError{reason: "token claims: do not decode into the type asked for", err: err}
	}

	return nil
}

// RFC 6750 section 3.1. The description is fixed: why a token was refused is for the server's log (server rule 2).
const (
	codeInvalidToken        = "invalid_token"
	descriptionInvalidToken = "invalid access token"
)

func (c *pepContext) verifyAuthorizationBearer() error {
	bearerToken, err := c.bearerCredentials()
	if errors.Is(err, ErrNoAuthorizationHeader) {
		// RFC 6750 Section 3: a 401 names the scheme it wants, here bare, so that it can carry resource_metadata.
		challenged := ErrNoAuthorizationHeader
		challenged.WWWAuthenticate = "Bearer"
		return challenged
	}
	if err != nil {
		return err
	}
	invalid := Error{
		HTTPStatus:      http.StatusUnauthorized,
		Code:            codeInvalidToken,
		Description:     descriptionInvalidToken,
		WWWAuthenticate: fmt.Sprintf(`Bearer error=%q, error_description=%q`, codeInvalidToken, descriptionInvalidToken),
	}
	token, err := c.pep.verifyAccessToken(c.request.Context(), bearerToken)
	if err != nil {
		return invalid
	}
	// A sender-constrained token is only good with its proof (RFC 9449 Section 7.2, RFC 9700 Section 4.10.1):
	// accepted as a bearer token, a leaked one would be replayed without it. The claims stay off the context,
	// so another enforcer of an any_of never sees a token this one refused.
	if token.Bound() {
		c.Slogger().Warn("Sender-constrained access token presented under the Bearer scheme")
		return invalid
	}
	c.accessTokenRaw = bearerToken
	c.accessToken = token
	c.claimsRaw = token.Payload
	return nil
}

// verifyAuthorizationDPoP checks a DPoP-bound access token and its proof (RFC 9449 Section 7.1):
// the DPoP-scheme credentials, the access token, and the proof for this request's method and URI,
// with ath and the key binding to the token's cnf.jkt. The URI is the configured public origin
// plus the request path, never one built from the client's Host or X-Forwarded-* headers.
func (c *pepContext) verifyAuthorizationDPoP(nonceRequired bool) error {
	if c.pep.publicOrigin == "" {
		return errors.New("DPoP needs the resource's public origin: set PublicOrigin or Resource")
	}
	accessToken, err := dpop.AccessToken(c.request.Header)
	if err != nil {
		return err
	}
	if err := c.verifyAccessToken(accessToken); err != nil {
		return &dpop.Error{Code: dpop.CodeInvalidToken, Description: descriptionInvalidToken}
	}
	// An unbound token has no cnf.jkt; the verifier refuses it as invalid_token.
	jkt := c.accessToken.Thumbprint()
	verifier := c.pep.dpopVerifier
	if nonceRequired {
		if c.pep.dpopNonceVerifier == nil {
			return errNoNonceSource
		}
		verifier = c.pep.dpopNonceVerifier
	}
	proof, err := verifier.Verify(c.request.Context(), c.request.Header, dpop.Request{
		Method:      c.request.Method,
		URI:         c.pep.publicOrigin + c.request.URL.EscapedPath(),
		AccessToken: accessToken,
		Thumbprint:  jkt,
	})
	if err != nil {
		return err
	}
	c.dpop = proof
	// Section 8.2: the next nonce rides on the successful response too, so the client need not be refused
	// once the current one expires.
	if nonceRequired {
		if next, err := c.pep.dpopNonces.Fresh(c.request.Context()); err == nil {
			handOutNonce(c.writer, next)
		} else {
			c.Slogger().Warn("No DPoP nonce for the response", "error", err)
		}
	}
	return nil
}

// errNoNonceSource refuses a request an enforcer requires a nonce for when the PEP has no nonce source:
// refusing beats checking proofs without the nonce.
var errNoNonceSource = Error{
	HTTPStatus:  http.StatusInternalServerError,
	Code:        "internal_error",
	Description: "DPoP nonces are not configured",
}

// handOutNonce sends nonce for the client's next proof (RFC 9449 Section 8.2), readable by scripts of
// another origin.
func handOutNonce(w http.ResponseWriter, nonce string) {
	dpop.SetNonce(w, nonce)
	w.Header().Add("Access-Control-Expose-Headers", "DPoP-Nonce")
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
		DPoPNonce:       e.Nonce,
	}
}

// bearerCredentials returns the credentials of the request's Authorization header under the Bearer scheme
// (RFC 6750 Section 2.1): exactly one header, the scheme compared case-insensitively (RFC 9110 Section
// 11.1), one or more spaces, and credentials in token68 syntax within maxAccessTokenBytes. Anything else is
// refused before a token is parsed (server rule 28).
func (c *pepContext) bearerCredentials() (string, error) {
	values := c.request.Header.Values("Authorization")
	switch len(values) {
	case 0:
		return "", ErrNoAuthorizationHeader
	case 1:
	default:
		return "", ErrInvalidAuthorizationHeader
	}
	scheme, rest, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", ErrInvalidAuthorizationHeader
	}
	token := strings.TrimLeft(rest, " ")
	if len(token) > maxAccessTokenBytes || !dpop.IsToken68(token) {
		return "", ErrInvalidAuthorizationHeader
	}
	return token, nil
}

// verifyAccessToken leaves the denial to the scheme's caller. VerifyAccessToken has logged why the token was refused.
func (c *pepContext) verifyAccessToken(accessToken string) error {
	jwtToken, err := c.pep.verifyAccessToken(c.request.Context(), accessToken)
	if err != nil {
		return err
	}
	c.accessTokenRaw = accessToken
	c.accessToken = jwtToken
	c.claimsRaw = jwtToken.Payload

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

// VerifyAccessToken parses and verifies a JWT access token against the configured JWKSet: its typ is at+jwt unless
// the PEP accepts untyped tokens (RFC 9068 Section 4), and its audience names the resource (RFC 9700 Section
// 4.10.2).
func (p *PEP) VerifyAccessToken(tokenRaw string) (*AccessToken, error) {
	return p.verifyAccessToken(context.Background(), tokenRaw)
}

// verifyAccessToken is VerifyAccessToken with the request's context, which a key source's Refresh is called with.
func (p *PEP) verifyAccessToken(ctx context.Context, tokenRaw string) (*AccessToken, error) {
	jwks, err := p.provideJwkSetFunc()
	if err != nil {
		return nil, fmt.Errorf("could not get JWKSet: %w", err)
	}
	payload, typ, err := verifyJWS(tokenRaw, jwks)
	// A kid the set does not hold may be the authorization server's next key; the set is asked once more, and the
	// key source decides whether that fetches.
	if errors.Is(err, errUnknownKeyID) && p.keySource != nil {
		refreshed, refreshErr := p.keySource.Refresh(ctx)
		if refreshErr != nil {
			p.slogger.Warn("could not refresh the JWKSet", "error", refreshErr)
		} else {
			payload, typ, err = verifyJWS(tokenRaw, refreshed)
		}
	}
	if err == nil && !p.acceptUntyped && !isAccessTokenType(typ) {
		err = errors.New("token typ is not at+jwt")
	}
	if err == nil {
		err = validateClaims(payload, p.now(), p.accessTokenAcceptableSkew, p.resource)
	}
	if err != nil {
		p.slogger.Warn("could not parse JWT", "error", err)
		return nil, fmt.Errorf("could not parse JWT: %w", err)
	}

	return &AccessToken{Payload: payload}, nil
}
