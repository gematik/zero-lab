// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

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
	IDPIss         string    `json:"idp_iss,omitempty"`
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
			IDPIss:         session.IDPIss,
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
