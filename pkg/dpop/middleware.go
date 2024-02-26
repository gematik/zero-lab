package dpop

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gematik/zero-lab/pkg/nonce"
)

type Middleware struct {
	nonceService nonce.NonceService
}

type MiddlewareOption func(*Middleware) error

func WithNonce(nonceService nonce.NonceService) MiddlewareOption {
	return func(d *Middleware) error {
		d.nonceService = nonceService
		return nil
	}
}

func NewMiddleware(opts ...MiddlewareOption) (*Middleware, error) {
	m := &Middleware{}
	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Middleware) VerifyRequest(request *http.Request, writer http.ResponseWriter, fullUrl string) (*DPoP, error) {
	dpopStr := request.Header.Get(DPoPHeaderName)
	if dpopStr == "" {
		writer.Header().Add("WWW-Authenticate", "Bearer, DPoP algs=\"ES256\"")
		writer.WriteHeader(http.StatusUnauthorized)
		return nil, errors.New("no dpop header")
	}

	dpop, err := ParseToken([]byte(dpopStr))
	if err != nil {
		writer.Header().Add("WWW-Authenticate", "Bearer, DPoP algs=\"ES256\"")
		writer.WriteHeader(http.StatusBadRequest)
		return nil, err
	}

	// verify the token
	// 1. check the method
	if dpop.HttpMethod != request.Method {
		slog.Error("method mismatch", "dpop", dpop.HttpURI, "request", request.Method)
		writer.Header().Add("WWW-Authenticate", "Bearer, DPoP algs=\"ES256\"")
		writer.WriteHeader(http.StatusBadRequest)
		return nil, errors.New("method mismatch")
	}
	// 2. check the url
	if dpop.HttpURI != fullUrl {
		slog.Error("url mismatch", "dpop", dpop.HttpMethod, "request", fullUrl)
		writer.Header().Add("WWW-Authenticate", "Bearer, DPoP algs=\"ES256\"")
		writer.WriteHeader(http.StatusBadRequest)
		return nil, errors.New("url mismatch")
	}

	return dpop, nil
}
