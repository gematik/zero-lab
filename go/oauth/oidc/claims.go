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

package oidc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"
)

// maxNumericDate is 9999-12-31T23:59:59Z, the last instant a time claim is read as.
const maxNumericDate = 253402300799

// Why a token's claims are refused.
var (
	ErrTokenExpired        = errors.New("token is expired")
	ErrTokenNotYetValid    = errors.New("token is not yet valid")
	ErrTokenIssuedInFuture = errors.New("token is issued in the future")
	ErrIssuerMismatch      = errors.New("token issuer does not match")
	// ErrNonceMismatch is an ID token that does not belong to this login.
	ErrNonceMismatch    = errors.New("id_token nonce does not match the login")
	ErrAudienceMismatch = errors.New("token audience does not match")
	ErrMissingClaim     = errors.New("token lacks a required claim")
)

// IDTokenChecks are what an ID token has to satisfy once its signature verified (OpenID Connect Core 1.0 section
// 3.1.3.7). The nonce only has to be there: comparing it to the one of the login is the caller's, who holds it.
type IDTokenChecks struct {
	Issuer   string
	ClientID string
	// Nonce is what the login sent, which binds the token to it (OIDC Core 3.1.3.7, step 11): without this, a
	// token obtained elsewhere could be injected into this login.
	Nonce string
	Now   time.Time
	Skew  time.Duration
}

// Validate checks the payload of a verified ID token. An empty expected Issuer or ClientID matches nothing, so a
// discovery document without an issuer cannot switch the check off.
func (c IDTokenChecks) Validate(payload []byte) error {
	claims, err := parseClaims(payload)
	if err != nil {
		return err
	}
	if c.Issuer == "" || claims.issuer == nil || *claims.issuer != c.Issuer {
		return ErrIssuerMismatch
	}
	if err := claims.checkAudience(c.ClientID); err != nil {
		return err
	}
	if claims.nonce == "" {
		return fmt.Errorf("%w: nonce", ErrMissingClaim)
	}
	if c.Nonce == "" || subtle.ConstantTimeCompare([]byte(claims.nonce), []byte(c.Nonce)) != 1 {
		return ErrNonceMismatch
	}
	if claims.expiry == nil {
		return fmt.Errorf("%w: exp", ErrMissingClaim)
	}
	return claims.checkLifetime(c.Now, c.Skew)
}

// ValidateLifetime checks the exp, nbf and iat of a payload, those it has, at the time now.
func ValidateLifetime(payload []byte, now time.Time, skew time.Duration) error {
	claims, err := parseClaims(payload)
	if err != nil {
		return err
	}
	return claims.checkLifetime(now, skew)
}

// ValidateAudience checks that the aud of a payload names clientID.
func ValidateAudience(payload []byte, clientID string) error {
	claims, err := parseClaims(payload)
	if err != nil {
		return err
	}
	return claims.checkAudience(clientID)
}

type claims struct {
	issuer    *string
	audience  []string
	nonce     string
	expiry    *time.Time
	notBefore *time.Time
	issuedAt  *time.Time
}

// parseClaims reads members by their exact names, since encoding/json would match a struct field case-insensitively
// and take "ISS" for the issuer.
func parseClaims(payload []byte) (*claims, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return nil, fmt.Errorf("token claims: %w", err)
	}
	if members == nil {
		return nil, errors.New("token claims: not an object")
	}

	var c claims
	var err error
	if raw, ok := members["iss"]; ok {
		issuer, err := stringClaim(raw)
		if err != nil {
			return nil, fmt.Errorf("token claim iss: %w", err)
		}
		c.issuer = &issuer
	}
	for _, name := range []string{"sub", "jti"} {
		if raw, ok := members[name]; ok {
			if _, err := stringClaim(raw); err != nil {
				return nil, fmt.Errorf("token claim %s: %w", name, err)
			}
		}
	}
	if raw, ok := members["aud"]; ok {
		if c.audience, err = audienceClaim(raw); err != nil {
			return nil, fmt.Errorf("token claim aud: %w", err)
		}
	}
	if raw, ok := members["nonce"]; ok {
		if c.nonce, err = stringClaim(raw); err != nil {
			return nil, fmt.Errorf("token claim nonce: %w", err)
		}
	}
	for name, target := range map[string]**time.Time{"exp": &c.expiry, "nbf": &c.notBefore, "iat": &c.issuedAt} {
		if raw, ok := members[name]; ok {
			date, err := numericDateClaim(raw)
			if err != nil {
				return nil, fmt.Errorf("token claim %s: %w", name, err)
			}
			*target = &date
		}
	}
	return &c, nil
}

func stringClaim(raw json.RawMessage) (string, error) {
	var value *string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	if value == nil {
		return "", errors.New("is null")
	}
	return *value, nil
}

// audienceClaim reads the single string or array of strings RFC 7519 section 4.1.3 allows.
func audienceClaim(raw json.RawMessage) ([]string, error) {
	if single, err := stringClaim(raw); err == nil {
		return []string{single}, nil
	}
	var list []*string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	if list == nil {
		return nil, errors.New("is null")
	}
	audience := make([]string, 0, len(list))
	for _, entry := range list {
		if entry == nil {
			return nil, errors.New("holds null")
		}
		audience = append(audience, *entry)
	}
	return audience, nil
}

// numericDateClaim keeps a fractional second, as RFC 7519 section 2 allows one, so that the comparisons do not move
// an expiry or a start by rounding.
func numericDateClaim(raw json.RawMessage) (time.Time, error) {
	var seconds *float64
	if err := json.Unmarshal(raw, &seconds); err != nil {
		return time.Time{}, err
	}
	if seconds == nil {
		return time.Time{}, errors.New("is null")
	}
	if math.Abs(*seconds) > maxNumericDate {
		return time.Time{}, errors.New("is out of range")
	}
	whole, fraction := math.Modf(*seconds)
	return time.Unix(int64(whole), int64(fraction*float64(time.Second))), nil
}

func (c *claims) checkAudience(clientID string) error {
	if c.audience == nil {
		return fmt.Errorf("%w: aud", ErrMissingClaim)
	}
	if clientID == "" || !slices.Contains(c.audience, clientID) {
		return ErrAudienceMismatch
	}
	return nil
}

// checkLifetime refuses at the instant of exp itself: RFC 7519 section 4.1.4 says "on or after".
func (c *claims) checkLifetime(now time.Time, skew time.Duration) error {
	if c.expiry != nil && !now.Before(c.expiry.Add(skew)) {
		return ErrTokenExpired
	}
	if c.notBefore != nil && now.Before(c.notBefore.Add(-skew)) {
		return ErrTokenNotYetValid
	}
	if c.issuedAt != nil && now.Before(c.issuedAt.Add(-skew)) {
		return ErrTokenIssuedInFuture
	}
	return nil
}
