package authzserver

import (
	"net/http"
)

// Implements https://datatracker.ietf.org/doc/html/rfc7591
func (s *Server) RegistrationEndpoint(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return &Error{
			HttpStatus:  http.StatusUnsupportedMediaType,
			Code:        "unsupported_media_type",
			Description: "content type must be application/json",
		}
	}

	return &Error{
		HttpStatus:  http.StatusNotImplemented,
		Code:        "not_implemented",
		Description: "registration endpoint is not implemented",
	}
}
