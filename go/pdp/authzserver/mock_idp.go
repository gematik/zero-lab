package authzserver

import (
	"net/http"
	"net/url"
)

// MockIDPConfig is a canned identity used in NonProdMode to complete login without a real OpenID Provider.
type MockIDPConfig struct {
	Subject string         `yaml:"subject"`
	Claims  map[string]any `yaml:"claims"`
}

// completeMockLogin finishes the authorization-code flow with the canned identity: it stashes the claims on
// the session, mints an authorization code, and redirects back to the client — the same tail as
// OPCallbackEndpoint, but with no upstream OP. NonProdMode only.
func (s *Server) completeMockLogin(w http.ResponseWriter, r *http.Request, session *AuthzServerSession) error {
	claims := map[string]any{}
	for k, v := range s.mockIDP.Claims {
		claims[k] = v
	}
	if s.mockIDP.Subject != "" {
		claims["sub"] = s.mockIDP.Subject
	}
	session.MockClaims = claims
	session.Code = generateNonce(64)
	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: "unable to save mock session: " + err.Error(),
		})
	}
	params := url.Values{}
	params.Set("code", session.Code)
	params.Set("state", session.State)
	http.Redirect(w, r, session.RedirectURI+"?"+params.Encode(), http.StatusFound)
	return nil
}
