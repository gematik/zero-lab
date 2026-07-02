package authzserver

import (
	"log/slog"
	"net/http"
)

// MountRoutes registers the authorization server routes on the given ServeMux. Each handler
// is wrapped by s.handle, which renders returned errors as OAuth JSON (RFC 6749 §5.2).
func (s *Server) MountRoutes(mux *http.ServeMux) {
	routes := []struct {
		method  string
		path    string
		handler handlerFunc
	}{
		{http.MethodGet, s.endpointPaths.AuthorizationServerMetadata, s.MetadataEndpoint},
		{http.MethodGet, s.endpointPaths.Jwks, s.JWKS},
		{http.MethodGet, s.endpointPaths.OpenIDProviders, s.OpenidProvidersEndpoint},
		{http.MethodGet, s.endpointPaths.Authorization, s.AuthorizationEndpoint},
		{http.MethodPost, s.endpointPaths.PushedAuthorizationRequest, s.PAREndpoint},
		{http.MethodGet, s.endpointPaths.OPCallback, s.OPCallbackEndpoint},
		{http.MethodGet, s.endpointPaths.GemIDPCallback, s.OPCallbackEndpoint},
		{http.MethodPost, s.endpointPaths.Token, s.TokenEndpoint},
		{http.MethodPost, s.endpointPaths.Introspection, s.IntrospectionEndpoint},
		{http.MethodGet, s.endpointPaths.Nonce, s.NonceEndpoint},
		{http.MethodPost, s.endpointPaths.Registration, s.RegistrationEndpoint},
	}
	for _, rt := range routes {
		mux.Handle(rt.method+" "+rt.path, s.handle(rt.handler))
		slog.Info("registered route", "method", rt.method, "path", rt.path)
	}

	if s.oidfRelyingParty != nil {
		mux.Handle(http.MethodGet+" "+s.endpointPaths.EntityStatement, http.HandlerFunc(s.oidfRelyingParty.Serve))
		slog.Info("registered route", "method", http.MethodGet, "path", s.endpointPaths.EntityStatement)
	}

	// Build-tag gated: mounts the co-hosted mock OP + registers it as a provider when built with -tags
	// mockidp; a no-op otherwise (the mockidp package is then not compiled or imported).
	s.registerMockProviders(mux)
}
