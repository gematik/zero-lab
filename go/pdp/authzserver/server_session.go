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

type AuthzServerSession struct {
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
	RequestUri          string                   `json:"request_uri"`
	AuthnClientSession  *oidc.AuthnClientSession `json:"authn_client_session"`
	Code                string                   `json:"code"`
	RefreshToken        string                   `json:"refresh_token"`
	RefreshCount        int                      `json:"refresh_count"`
	LastRefreshAt       time.Time                `json:"last_refresh_at"`
	DPoPThumbprint      string                   `json:"dpop_thumbprint"`
}

type AuthzServerSessionStore interface {
	GetAuthzServerSessionByID(id string) (*AuthzServerSession, error)
	GetAuthzServerSessionByAuthnState(authnState string) (*AuthzServerSession, error)
	GetAutzhServerSessionByRequestURI(requestURI string) (*AuthzServerSession, error)
	GetAuthzServerSessionByCode(code string) (*AuthzServerSession, error)
	GetAuthzServerSessionByRefreshToken(token string) (*AuthzServerSession, error)
	DeleteRefreshIndex(refreshTokenHash string) error
	SaveAutzhServerSession(session *AuthzServerSession) error
	DeleteAuthzServerSessionByID(id string) error
}
