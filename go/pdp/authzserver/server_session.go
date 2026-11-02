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
	"time"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

// Session is the state of one authorization, from the pushed request to the last token refresh.
// RefreshToken holds the hash of the current refresh token, not the token.
type Session struct {
	ID                  string                   `json:"id"`
	CreatedAt           time.Time                `json:"created_at"`
	ExpiresAt           time.Time                `json:"expires_at"`
	AccessTokenDuration time.Duration            `json:"access_token_duration"`
	Audience            []string                 `json:"audience"`
	ClientID            string                   `json:"client_id"`
	RedirectURI         string                   `json:"redirect_uri"`
	CodeChallenge       string                   `json:"code_challenge"`
	CodeChallengeMethod string                   `json:"code_challenge_method"`
	State               string                   `json:"state"`
	Scopes              []string                 `json:"scopes"`
	IDPIss              string                   `json:"idp_iss"`
	RequestURI          string                   `json:"request_uri"`
	AuthnClientSession  *oidc.AuthnClientSession `json:"authn_client_session"`
	Code                string                   `json:"code"`
	RefreshToken        string                   `json:"refresh_token"`
	RefreshCount        int                      `json:"refresh_count"`
	LastRefreshAt       time.Time                `json:"last_refresh_at"`
	DPoPThumbprint      string                   `json:"dpop_thumbprint"`
}

// SessionStore persists sessions and finds them by their lookup values. The lookup by request_uri
// consumes it, so a pushed request starts one login at most.
type SessionStore interface {
	GetAuthzServerSessionByID(id string) (*Session, error)
	GetAuthzServerSessionByAuthnState(authnState string) (*Session, error)
	GetAutzhServerSessionByRequestURI(requestURI string) (*Session, error)
	GetAuthzServerSessionByCode(code string) (*Session, error)
	GetAuthzServerSessionByRefreshToken(token string) (*Session, error)
	DeleteRefreshIndex(refreshTokenHash string) error
	SaveAutzhServerSession(session *Session) error
	DeleteAuthzServerSessionByID(id string) error
}
