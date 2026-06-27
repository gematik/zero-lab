//go:build !mockidp

package authzserver

import "net/http"

// registerMockProviders is a no-op in production builds (the mockidp package is not compiled or imported).
func (s *Server) registerMockProviders(mux *http.ServeMux) {}
