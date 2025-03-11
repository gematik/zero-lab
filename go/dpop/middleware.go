package dpop

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gematik/zero-lab/go/nonce"
)

type Middleware struct {
	nonceService nonce.Service
}

type MiddlewareOption func(*Middleware) error

func WithNonceService(nonceService nonce.Service) MiddlewareOption {
	return func(m *Middleware) error {
		m.nonceService = nonceService
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

func (m *Middleware) addWwwAuthenticateHeader(writer http.ResponseWriter) {
	writer.Header().Add("WWW-Authenticate", `DPoP algs="ES256"`)
}

func (m *Middleware) addNonceHeader(writer http.ResponseWriter) {
	if m.nonceService == nil {
		return
	}

	nonce, err := m.nonceService.Get()
	if err != nil {
		slog.Error("failed to generate nonce", "error", err)
		return
	}

	writer.Header().Add("DPoP-Nonce", nonce)
}

func (m *Middleware) VerifyRequest(request *http.Request, writer http.ResponseWriter, fullUrl string) (*DPoP, error) {
	dpopStr := request.Header.Get(DPoPHeaderName)
	if dpopStr == "" {
		slog.Error("no dpop header")
		m.addWwwAuthenticateHeader(writer)
		m.addNonceHeader(writer)
		writer.WriteHeader(http.StatusUnauthorized)
		return nil, errors.New("no dpop header")
	}

	dpop, err := Parse(dpopStr)
	if err != nil {
		slog.Error("failed to parse dpop header", "error", err)
		m.addWwwAuthenticateHeader(writer)
		writer.WriteHeader(http.StatusBadRequest)
		return nil, err
	}

	// verify the token
	// 1. check the method
	if dpop.HttpMethod != request.Method {
		slog.Error("method mismatch", "dpop", dpop.HttpURI, "request", request.Method)
		m.addWwwAuthenticateHeader(writer)
		writer.WriteHeader(http.StatusBadRequest)
		return nil, errors.New("method mismatch")
	}
	// 2. check the url
	if dpop.HttpURI != fullUrl {
		slog.Error("url mismatch", "dpop", dpop.HttpMethod, "request", fullUrl)
		m.addWwwAuthenticateHeader(writer)
		writer.WriteHeader(http.StatusBadRequest)
		return nil, errors.New("url mismatch")
	}

	return dpop, nil
}
