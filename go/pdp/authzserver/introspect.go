package authzserver

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// IntrospectionResponse is the OAuth 2.0 Token Introspection response (RFC 7662), extended per §2.2
// with the brokered upstream OIDC identity and session metadata as service-specific members.
type IntrospectionResponse struct {
	Active    bool           `json:"active"`
	Scope     string         `json:"scope,omitempty"`
	ClientID  string         `json:"client_id,omitempty"`
	Username  string         `json:"username,omitempty"`
	TokenType string         `json:"token_type,omitempty"`
	Exp       int64          `json:"exp,omitempty"`
	Iat       int64          `json:"iat,omitempty"`
	Sub       string         `json:"sub,omitempty"`
	Aud       []string       `json:"aud,omitempty"`
	Iss       string         `json:"iss,omitempty"`
	Jti       string         `json:"jti,omitempty"`
	Cnf       map[string]any `json:"cnf,omitempty"`

	// Extension members: the upstream identity this session was established with, and session details.
	Identity map[string]any       `json:"identity,omitempty"`
	IDToken  string               `json:"id_token,omitempty"`
	Session  *IntrospectedSession `json:"session,omitempty"`
}

type IntrospectedSession struct {
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	OPIssuer       string    `json:"op_issuer,omitempty"`
	RedirectURI    string    `json:"redirect_uri,omitempty"`
	DPoPThumbprint string    `json:"dpop_thumbprint,omitempty"`
}

// IntrospectionEndpoint implements OAuth 2.0 Token Introspection (RFC 7662). The caller must
// authenticate as a client, and only the client a token was issued to may introspect it; any other
// outcome answers {"active": false} so a token is never revealed to a party that does not own it.
func (s *Server) IntrospectionEndpoint(w http.ResponseWriter, r *http.Request) error {
	client, _, clientErr := s.verifyClient(r)
	if clientErr != nil {
		return clientErr
	}

	tokenRaw := r.FormValue("token")
	if tokenRaw == "" {
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing token parameter")
	}

	token, err := s.tokenVerifier.VerifyAccessToken(tokenRaw)
	if err != nil {
		return writeJSON(w, http.StatusOK, IntrospectionResponse{Active: false})
	}

	var jti string
	if err := token.Get("jti", &jti); err != nil || jti == "" {
		return writeJSON(w, http.StatusOK, IntrospectionResponse{Active: false})
	}

	session, err := s.sessionStore.GetAuthzServerSessionByID(jti)
	if err != nil {
		return writeJSON(w, http.StatusOK, IntrospectionResponse{Active: false})
	}

	// RFC 7662 §4: only the client the token was issued to may introspect it.
	if session.ClientID != client.ClientID {
		slog.Warn("introspection denied: caller is not the token's client",
			"caller", client.ClientID, "token_client", session.ClientID)
		return writeJSON(w, http.StatusOK, IntrospectionResponse{Active: false})
	}

	tokenType := "Bearer"
	if session.DPoPThumbprint != "" {
		tokenType = "DPoP"
	}

	resp := IntrospectionResponse{
		Active:    true,
		Scope:     strings.Join(session.Scopes, " "),
		ClientID:  session.ClientID,
		TokenType: tokenType,
		Sub:       session.ClientID,
		Aud:       session.Audience,
		Iss:       s.Metadata.Issuer,
		Jti:       session.ID,
		Session: &IntrospectedSession{
			CreatedAt:      session.CreatedAt,
			ExpiresAt:      session.ExpiresAt,
			OPIssuer:       session.OPIssuer,
			RedirectURI:    session.RedirectURI,
			DPoPThumbprint: session.DPoPThumbprint,
		},
	}
	if exp, ok := token.Expiration(); ok {
		resp.Exp = exp.Unix()
	}
	if iat, ok := token.IssuedAt(); ok {
		resp.Iat = iat.Unix()
	}
	if session.DPoPThumbprint != "" {
		resp.Cnf = map[string]any{"jkt": session.DPoPThumbprint}
	}

	// Upstream OIDC identity, present only for sessions established via an upstream login.
	if as := session.AuthnClientSession; as != nil && as.TokenResponse != nil && as.TokenResponse.IDTokenRaw != "" {
		identity := map[string]any{}
		if err := as.TokenResponse.Claims(&identity); err == nil {
			resp.Identity = identity
			resp.IDToken = as.TokenResponse.IDTokenRaw
			if sub, ok := identity["sub"].(string); ok && sub != "" {
				resp.Sub = sub
			}
			resp.Username = firstNonEmpty(identity, "preferred_username", "name", "email")
		}
	}

	return writeJSON(w, http.StatusOK, resp)
}

func firstNonEmpty(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
