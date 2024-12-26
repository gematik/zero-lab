// Description: This implementation of PEP is using other patterns
// of Go language - private structures and builder pattern. Additionally,
// we use only standard http package to introduce the middleware to intercept
// and validate the requests.
package pep2

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

type Error struct {
	HttpStatus  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

var ErrForbiddenHeadersInRequest = &Error{
	HttpStatus:  400,
	Code:        "forbidden_headers_in_request",
	Description: "Request contains forbidden headers",
}

var ErrNoAuthorizationHeader = &Error{
	HttpStatus:  400,
	Code:        "no_authorization_header",
	Description: "No Authorization header in request",
}

var ErrInvalidAuthorizationHeader = &Error{
	HttpStatus:  400,
	Code:        "invalid_authorization_header",
	Description: "Invalid Authorization header in request",
}

var ErrAccessDenied = &Error{
	HttpStatus:  403,
	Code:        "access_denied",
	Description: "Access denied",
}

type pep struct {
}

func (p *pep) GuardedHandlerFunc(guard Guard, next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guard.Run(next.ServeHTTP, p.deny).ServeHTTP(w, r)
	})
}

func (p *pep) deny(w http.ResponseWriter, r *http.Request) {
	slog.Debug("Request denied", "method", r.Method, "url", r.URL)
	w.WriteHeader(http.StatusForbidden)
}

type builder struct {
}

func (p *pep) NewGuard() *guardBuilder {
	return &guardBuilder{p: p}
}

func NewBuilder() *builder {
	return &builder{}
}

func (b *builder) Build() (*pep, error) {
	return &pep{}, nil
}

type Guard interface {
	Run(allow, deny http.HandlerFunc) http.Handler
}

type guardBuilder struct {
	p     *pep
	err   error
	guard Guard
}

func (b *guardBuilder) Build() (Guard, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.guard == nil {
		return nil, errors.New("no guard to build")
	}
	return b.guard, nil
}

func (b *guardBuilder) Guard(g Guard) *guardBuilder {
	if b.err != nil {
		return b
	}
	if b.guard != nil {
		b.err = errors.New("multiple guards not allowed. use OneOf() or AllOf()")
		return b
	}
	b.guard = g
	return b
}

func (b *guardBuilder) DenyAll() *guardBuilder {
	return b.Guard(&DenyAllGuard{})
}

type DenyAllGuard struct{}

func (d *DenyAllGuard) Run(allow, deny http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Denying all requests")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ErrAccessDenied)
		deny(w, r)
	})
}
