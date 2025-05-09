package pep

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type PEP struct {
	slogger                   *slog.Logger
	httpClient                *http.Client
	provideJwkSetFunc         func() (jwk.Set, error)
	decryptAccessTokenFunc    func(string) (string, error)
	accessTokenAcceptableSkew time.Duration
	resource                  string // URI of the resource being protected

}

type builder struct {
	p   *PEP
	err error
}

func NewBuilder() *builder {
	return &builder{p: &PEP{}}
}

func (b *builder) Build() (*PEP, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.p.provideJwkSetFunc == nil {
		return nil, errors.New("none of the JWKSet provider has been set")
	}
	if b.p.httpClient == nil {
		b.p.httpClient = http.DefaultClient
	}
	if b.p.slogger == nil {
		b.p.slogger = slog.Default()
	}
	if b.p.accessTokenAcceptableSkew == 0 {
		b.p.accessTokenAcceptableSkew = 1 * time.Minute
	}
	return b.p, nil
}

func (b *builder) WithJWKSetFunc(f func() (jwk.Set, error)) *builder {
	b.p.provideJwkSetFunc = f
	return b
}

func (b *builder) WithJWKSet(jwkSet jwk.Set) *builder {
	b.p.provideJwkSetFunc = func() (jwk.Set, error) {
		return jwkSet, nil
	}
	return b
}

func (b *builder) WithJWKSetPath(path string) *builder {
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

func (b *builder) WithAccessTokenAcceptableSkew(d time.Duration) *builder {
	b.p.accessTokenAcceptableSkew = d
	return b
}

func (b *builder) WithDecryptAccessTokenFunc(f func(string) (string, error)) *builder {
	b.p.decryptAccessTokenFunc = f
	return b
}

func (b *builder) WithHttpClient(client *http.Client) *builder {
	b.p.httpClient = client
	return b
}

func (b *builder) WithSlogger(slogger *slog.Logger) *builder {
	b.p.slogger = slogger
	return b
}

func (b *builder) Resource(resource string) *builder {
	b.p.resource = resource
	return b
}

// close the PEP and release any resources
func (p *PEP) Close() error {
	// TODO: reserved for future use
	return nil
}

func (p *PEP) deny(ctx Context, err Error) {
	w := ctx.Writer()
	r := ctx.Request()
	slog.Debug("Request denied", "method", r.Method, "url", r.URL)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(err.HttpStatus)
	json.NewEncoder(w).Encode(err)
}

type HandlerFunc func(ctx Context)

type Context interface {
	Writer() http.ResponseWriter
	Request() *http.Request
	Deny(err Error)
	WithDeny(deny func(c Context, err Error)) Context
	Slogger() *slog.Logger
	UnmarshalClaims(claims any) error
}

type pepContext struct {
	pep            *PEP
	slogger        *slog.Logger
	writer         http.ResponseWriter
	request        *http.Request
	deny           func(Context, Error)
	accessTokenRaw string
	accessToken    jwt.Token
	dpop           *dpop.DPoP
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

func (c *pepContext) verifyAuthorizationDPoP(options dpop.ParseOptions) error {
	proof, dpopErr := dpop.ParseRequest(c.request, options)
	if dpopErr != nil {
		return dpopErr
	}

	if err := c.verifyAccessToken(proof.AccessTokenRaw); err != nil {
		return err
	}

	// verify access token binding
	cnf := new(map[string]interface{})

	c.accessToken.Get("cnf", cnf)
	if (*cnf)["jkt"] == "" {
		return ErrMissingAccessTokenDPoPBinding
	}
	if proof.DPoP.KeyThumbprint != (*cnf)["jkt"] {
		return ErrInvalidAccessTokenDPoPBinding
	}
	c.dpop = proof.DPoP

	return nil
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
	jwtToken, err := c.pep.verifyAccessToken(accessToken)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusUnauthorized,
			Code:        "invalid_token",
			Description: fmt.Sprintf("invalid access token: %s", err),
		}
	}
	c.accessTokenRaw = accessToken
	c.accessToken = jwtToken

	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	claimsSegment := parts[1]
	claimsRaw, err := base64.RawURLEncoding.DecodeString(claimsSegment)
	if err != nil {
		return fmt.Errorf("invalid JWT claims segment: %w", err)
	}

	c.claimsRaw = claimsRaw

	return nil
}

func (p *PEP) NewContext(w http.ResponseWriter, r *http.Request) Context {
	return &pepContext{
		pep:     p,
		slogger: p.slogger,
		writer:  w,
		request: r,
		deny:    p.deny,
	}
}

func (p *PEP) GuardedHandlerFunc(enforcer Enforcer, next func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := p.NewContext(w, r)
		enforcer.Apply(ctx, func(ctx Context) {
			next(ctx.Writer(), ctx.Request())
		})
	}
}

func (p *PEP) verifyAccessToken(tokenRaw string) (jwt.Token, error) {
	jwks, err := p.provideJwkSetFunc()
	if err != nil {
		return nil, fmt.Errorf("could not get JWKSet: %w", err)
	}
	token, err := jwt.ParseString(
		tokenRaw,
		jwt.WithAcceptableSkew(p.accessTokenAcceptableSkew),
		jwt.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithAudience(p.resource),
	)

	if err != nil {
		p.slogger.Warn("could not parse JWT", "error", err, "token", tokenRaw)
		return nil, fmt.Errorf("could not parse JWT: %w", err)
	}

	return token, nil

}
