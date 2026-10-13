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

package bff

import (
	"time"
)

type Session struct {
	ID                   string         `json:"id"`
	State                string         `json:"state"`
	CreatedAt            time.Time      `json:"created_at"`
	CodeVerifier         string         `json:"code_verifier"`
	CodeChallengeMethod  string         `json:"code_challenge_method"`
	AccessToken          string         `json:"access_token"`
	AccessTokenExpiresAt time.Time      `json:"access_token_expires_at"`
	RefreshToken         string         `json:"refresh_token"`
	Identity             map[string]any `json:"identity,omitempty"`
}

type SessionManager interface {
	CreateSession(state string, codeVerifier string, codeChallengeMethod string) (*Session, error)
	UpdateSession(session *Session) error
	GetSessionByState(state string) (*Session, error)
	GetSessionByID(id string) (*Session, error)
	DeleteSessionByID(id string) error
}
