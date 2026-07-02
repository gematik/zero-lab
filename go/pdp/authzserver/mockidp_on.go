//go:build mockidp

package authzserver

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/pdp/authzserver/mockidp"
)

// mockHost adapts *Server to mockidp.Host so the subpackage never imports authzserver (no import cycle).
type mockHost struct{ s *Server }

func (h mockHost) IssuerBaseURL() string { return h.s.Metadata.Issuer }
func (h mockHost) OPCallbackURL() string {
	return strings.TrimRight(h.s.Metadata.Issuer, "/") + h.s.endpointPaths.OPCallback
}
func (h mockHost) AddProvider(c oidc.Client) { h.s.openidProviders = append(h.s.openidProviders, c) }

// registerMockProviders mounts the co-hosted mock OP and registers it as a normal provider. Compiled only
// with `-tags mockidp`; the !mockidp build is a no-op and never imports the mockidp package.
func (s *Server) registerMockProviders(mux *http.ServeMux) {
	id := mockidp.Identity{
		Subject: "X110000001",
		Claims:  map[string]any{"name": "Test User", "email": "test@example.com"},
	}
	if err := mockidp.Register(mockHost{s}, mux, id); err != nil {
		slog.Error("mock IdP registration failed", "error", err)
		return
	}
	slog.Warn("mock IdP registered — built with -tags mockidp, NON-PRODUCTION ONLY")
}
