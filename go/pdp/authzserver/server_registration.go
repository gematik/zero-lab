package authzserver

import (
	"net/http"
)

// RegistrationEndpoint is intentionally closed. Clients are provisioned out-of-band (operator config now,
// federation later), so dynamic client registration (RFC 7591) is not offered. The endpoint stays advertised
// in the metadata and returns a coherent OAuth error — the same shape as every other endpoint — rather than a
// bare 404, leaving a clean seam to enable gated registration later (swap this body, add storage).
func (s *Server) RegistrationEndpoint(w http.ResponseWriter, r *http.Request) error {
	return oauthErr(http.StatusForbidden, "access_denied",
		"dynamic client registration is not supported; clients are provisioned out-of-band")
}
