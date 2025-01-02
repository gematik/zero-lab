package pep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Config struct {
	JWKSetPath string `json:"jwks_path,omitempty"`
}

type PEP struct {
	slogger                *slog.Logger
	httpClient             *http.Client
	jwkSetFunc             func() (jwk.Set, error)
	decryptAccessTokenFunc func(string) (string, error)
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
	if b.p.jwkSetFunc == nil {
		return nil, errors.New("none of the JWKSet provider has been set")
	}
	if b.p.httpClient == nil {
		b.p.httpClient = http.DefaultClient
	}
	if b.p.slogger == nil {
		b.p.slogger = slog.Default()
	}
	return b.p, nil
}

func (b *builder) WithJWKSetFunc(f func() (jwk.Set, error)) *builder {
	b.p.jwkSetFunc = f
	return b
}

func (b *builder) WithJWKSet(jwkSet jwk.Set) *builder {
	b.p.jwkSetFunc = func() (jwk.Set, error) {
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
	Claims(claims any) error
}

type pepContext struct {
	pep            *PEP
	slogger        *slog.Logger
	writer         http.ResponseWriter
	request        *http.Request
	deny           func(Context, Error)
	accessTokenRaw string
	accessToken    jwt.Token
	claimsRaw      []byte
}

func (c pepContext) Writer() http.ResponseWriter {
	return c.writer
}

func (c pepContext) Request() *http.Request {
	return c.request
}

func (c pepContext) Deny(err Error) {
	c.deny(c, err)
}

func (c pepContext) WithDeny(deny func(Context, Error)) Context {
	c.deny = deny
	return c
}

func (c pepContext) Slogger() *slog.Logger {
	return c.slogger
}

func (c pepContext) Claims(claims any) error {
	if err := c.assureAccessToken(); err != nil {
		return err
	}
	if err := json.Unmarshal(c.claimsRaw, claims); err != nil {
		return fmt.Errorf("unable to unmarshal claims: %w", err)
	}

	return nil
}

func (c *pepContext) assureAccessToken() error {
	authzHeaders := c.request.Header.Values("Authorization")
	if len(authzHeaders) == 0 {
		return ErrNoAuthorizationHeader
	}

	// we support bearer and dpop
	// we ignore other authz headers
	for _, authzHeader := range authzHeaders {
		parts := strings.Split(authzHeader, " ")
		if len(parts) != 2 {
			continue
		}

		tokenType := strings.ToLower(parts[0])
		if tokenType == "bearer" {
			token, err := c.pep.verifyAccessToken(parts[1])
			if err != nil {
				return &Error{
					HttpStatus:  http.StatusUnauthorized,
					Code:        "invalid_token",
					Description: fmt.Sprintf("invalid access token: %s", err),
				}
			}
			c.accessTokenRaw = parts[1]
			c.accessToken = token
			asMap, err := c.accessToken.AsMap(context.Background())
			if err != nil {
				return fmt.Errorf("unable to convert token to map: %w", err)
			}

			if c.claimsRaw, err = json.Marshal(asMap); err != nil {
				return fmt.Errorf("unable to process claims: %w", err)
			}

			return nil
		}
	}

	return ErrInvalidAuthorizationHeader
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
	jwks, err := p.jwkSetFunc()
	if err != nil {
		return nil, fmt.Errorf("could not get JWKSet: %w", err)
	}
	token, err := jwt.ParseString(
		tokenRaw,
		jwt.WithAcceptableSkew(1*time.Minute),
		jwt.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)),
	)

	if err != nil {
		p.slogger.Error("could not parse JWT", "error", err, "token", tokenRaw)
		return nil, fmt.Errorf("could not parse JWT: %w", err)
	}

	return token, nil

}
