package proxy

import (
	"context"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Provider is a selectable identity provider for the sign-in chooser.
type Provider struct {
	Issuer  string `json:"iss"`
	Name    string `json:"name"`
	LogoURI string `json:"logo_uri,omitempty"`
	Type    string `json:"type"` // "oidc" | "oidf" | "gemidp"
}

// LoginStart is the result of beginning a login. Mode "redirect" means the browser navigates to AuthURL;
// "decoupled" means AuthURL is rendered as a QR for a second device (with an on-device redirect offered too).
type LoginStart struct {
	AuthURL  string
	Mode     string // "redirect" | "decoupled"
	Provider *Provider
}

// Backend is the auth backend the /oauth2/* handlers drive. Two implementations: providerBackend (drives
// oidc.Client providers directly and issues a local session) and pdpBackend (an OAuth client of the PDP,
// like the bff — added later). Keeping the handlers behind this interface keeps them backend-agnostic.
type Backend interface {
	// Providers lists the IdPs for the chooser.
	Providers(ctx context.Context) ([]Provider, error)

	// DefaultIssuer returns the issuer to auto-start with when no idp_iss is given (a single configured
	// provider), or "" to show the chooser.
	DefaultIssuer() string

	// StartLogin builds the authorization request for idpIss ("" = the default/single provider), mutating
	// sess (IDPIss, State, Nonce, CodeVerifier, CodeChallengeMethod) before it is persisted.
	StartLogin(ctx context.Context, sess *Session, idpIss, scope string) (LoginStart, error)

	// Complete handles the redirect_uri callback: exchanges code (using sess.State/CodeVerifier/IDPIss) and
	// fills sess.Identity (and, for the PDP backend, the tokens).
	Complete(ctx context.Context, sess *Session, code string) error

	// FreshAccessToken returns a non-expired upstream access token (refreshing + persisting as needed), or
	// "" when the backend keeps no forwardable token (e.g. direct providers).
	FreshAccessToken(ctx context.Context, sess *Session) (string, error)

	// DPoPKey is the key DPoP injection proofs are minted with, or nil when unsupported.
	DPoPKey() jwk.Key
}

// proxyRoute is an extra HTTP route a backend asks the server to mount outside /oauth2/* (e.g. the OIDF
// relying-party entity statement at /.well-known/openid-federation).
type proxyRoute struct {
	Pattern string
	Handler http.Handler
}

// routeProvider is optionally implemented by a Backend that needs extra top-level routes mounted.
type routeProvider interface {
	proxyRoutes() []proxyRoute
}
