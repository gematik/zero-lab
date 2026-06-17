package authzserver

import (
	"net/http"
)

// Implements https://datatracker.ietf.org/doc/html/rfc7591
func (s *Server) RegistrationEndpoint(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return oauthErr(http.StatusUnsupportedMediaType, "unsupported_media_type", "content type must be application/json")
	}

	return oauthErr(http.StatusNotImplemented, "not_implemented", "registration endpoint is not implemented")
}
