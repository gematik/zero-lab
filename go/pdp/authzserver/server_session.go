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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/gematik/zero-lab/go/openid"
)

// Session is the state of one authorization, from the pushed request to the last token refresh.
// RefreshToken holds the hash of the current refresh token, not the token.
type Session struct {
	ID                  string                     `json:"id"`
	CreatedAt           time.Time                  `json:"created_at"`
	ExpiresAt           time.Time                  `json:"expires_at"`
	AccessTokenDuration time.Duration              `json:"access_token_duration"`
	Audience            []string                   `json:"audience"`
	ClientID            string                     `json:"client_id"`
	RedirectURI         string                     `json:"redirect_uri"`
	CodeChallenge       string                     `json:"code_challenge"`
	CodeChallengeMethod string                     `json:"code_challenge_method"`
	State               string                     `json:"state"`
	Scopes              []string                   `json:"scopes"`
	IDPIss              string                     `json:"idp_iss"`
	RequestURI          string                     `json:"request_uri"`
	AuthnClientSession  *openid.AuthnClientSession `json:"authn_client_session"`
	Code                string                     `json:"code"`
	RefreshToken        string                     `json:"refresh_token"`
	RefreshCount        int                        `json:"refresh_count"`
	LastRefreshAt       time.Time                  `json:"last_refresh_at"`
	DPoPThumbprint      string                     `json:"dpop_thumbprint"`
}

// ErrSessionNotFound is what a [SessionStore] returns for a session that does not exist, has expired or was
// consumed, and for a record it cannot open: the client can do nothing about either but start again.
var ErrSessionNotFound = errors.New("session not found")

// SessionStore persists sessions and finds them by their lookup values. The lookups by authentication state,
// request_uri and code consume the value, so each answers once even under concurrent requests (RFC 9126
// Section 4, RFC 6749 Section 4.1.2, RFC 9700 Section 2.1). Save writes a session and all its lookup values
// at once, so a lookup never resolves a half-written session; it indexes every lookup value the session holds, so
// a caller clears a consumed value before it saves the session again. A session without ExpiresAt is kept for
// [DefaultSessionTTL]. RefreshToken arrives as a hash already; the other lookup values are secrets that an
// implementation keeps out of anything it stores in the clear.
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

// hashRefreshToken maps a raw refresh token to its stored form. Only the hash is persisted (in the session
// record and the refresh lookup), so a rogue storage admin learns hashes, not replayable tokens. The raw token
// exists only in transit (issued in the token response, presented back on refresh).
func hashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
