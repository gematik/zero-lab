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

package oidf

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gematik/zero-lab/go/openid"
)

// Bounds of the values the federation hands over as data.
const (
	// maxTextBytes bounds a text member: a claim of the ID token, a name on the IdP list.
	maxTextBytes = 1024
	// maxEntityIdentifierBytes bounds an entity identifier or another URL taken as data.
	maxEntityIdentifierBytes = 2048
)

// checkText takes valid UTF-8 of at most most bytes without control characters (Cc), which would let a value break a
// log line or a header it is written into, and without format characters (Cf: bidi overrides, zero-width characters)
// and line or paragraph separators (Zl, Zp), which would make it read otherwise than it is. The error names the rule,
// never the value.
func checkText(value string, most int) error {
	if len(value) > most {
		return fmt.Errorf("longer than %d bytes", most)
	}
	if !utf8.ValidString(value) {
		return errors.New("not UTF-8")
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return errors.New("holds a control or format character")
		}
	}
	return nil
}

// textMember reads the member name of an object as text within most bytes. A member that is absent or null is not
// present; one of another type is an error.
func textMember(members map[string]json.RawMessage, name string, most int) (value string, present bool, err error) {
	raw, ok := members[name]
	if !ok || string(raw) == "null" {
		return "", false, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false, errors.New("is no text")
	}
	if err := checkText(value, most); err != nil {
		return "", false, err
	}
	return value, true, nil
}

// Bounds of the values one login carries.
const (
	// maxStateBytes bounds state and nonce: sektorale IDPs and the gematik reference IDP refuse 513 characters.
	maxStateBytes = 512
	// minVerifierBytes and maxVerifierBytes are the length of a code_verifier (RFC 7636 section 4.1).
	minVerifierBytes = 43
	maxVerifierBytes = 128
)

// The login values the relying party refuses before a request leaves. Each error names the field, never the value.
var (
	ErrState        = errors.New("state refused")
	ErrNonce        = errors.New("nonce refused")
	ErrCodeVerifier = errors.New("code_verifier refused")
	// ErrScopeNotRegistered is a scope outside the scope the relying party registered, which the IDP compares the
	// request against.
	ErrScopeNotRegistered = errors.New("scope not registered")
	// ErrACRValues is an acr value that is no gematik level of assurance.
	ErrACRValues = errors.New("acr values refused")
	// ErrClaimNotSupported is a claim the IDP does not list in its claims_supported (gemSpec_IDP_Sek A_24403).
	ErrClaimNotSupported = errors.New("claim not supported by the IDP")
	// ErrClaimsRequest is a claims parameter whose members are not as OIDC Core 5.5 has them.
	ErrClaimsRequest = errors.New("claims request refused")
)

// The levels of assurance of the TI federation (gemSpec_IDP_Sek Tabelle 7, gemSpec_IDP_FD), ranked low < substantial
// < high.
const (
	LoALow         = "gematik-ehealth-loa-low"
	LoASubstantial = "gematik-ehealth-loa-substantial"
	LoAHigh        = "gematik-ehealth-loa-high"
)

var loaRank = map[string]int{LoALow: 1, LoASubstantial: 2, LoAHigh: 3}

// checkACRValues takes acr values that are gematik levels of assurance. The ID token's acr is held to the lowest of
// them (checkIdentity), so asking for a lower level never lets a lower authentication through unnoticed.
func checkACRValues(values []string) error {
	for _, acr := range values {
		if _, known := loaRank[acr]; !known {
			return fmt.Errorf("%w: not a gematik level of assurance", ErrACRValues)
		}
	}
	return nil
}

// grantedScopes reads the scope of a token response, space-separated scope-tokens of NQCHAR (RFC 6749 section 3.3);
// without one, the scopes asked for were granted (section 5.1).
func grantedScopes(scope string, asked []string) ([]string, error) {
	if scope == "" {
		return slices.Clone(asked), nil
	}
	if len(scope) > maxTextBytes {
		return nil, fmt.Errorf("%w: the granted scope is longer than %d bytes", ErrIdentityClaim, maxTextBytes)
	}
	scopes := strings.Split(scope, " ")
	for _, token := range scopes {
		if token == "" {
			return nil, fmt.Errorf("%w: the granted scope has an empty token", ErrIdentityClaim)
		}
		for _, c := range []byte(token) {
			if c != 0x21 && (c < 0x23 || c > 0x7e || c == 0x5c) {
				return nil, fmt.Errorf("%w: the granted scope has a character outside NQCHAR", ErrIdentityClaim)
			}
		}
	}
	return scopes, nil
}

// checkLogin refuses the values of a login the relying party would send badly, before any request is made. scopes are
// the login's or the configured ones, registered is the scope the relying party registered, and supported the IDP's
// claims_supported, empty when it names none.
func checkLogin(login openid.Login, scopes []string, registered string, supported []string) error {
	if err := checkStateOrNonce(ErrState, login.State); err != nil {
		return err
	}
	if err := checkStateOrNonce(ErrNonce, login.Nonce); err != nil {
		return err
	}
	if err := checkVerifier(login.Verifier); err != nil {
		return err
	}
	allowed := strings.Fields(registered)
	for _, scope := range scopes {
		if !slices.Contains(allowed, scope) {
			return ErrScopeNotRegistered
		}
	}
	if err := checkACRValues(login.ACRValues); err != nil {
		return err
	}
	request, err := parseClaimsRequest(login.Claims)
	if err != nil {
		return err
	}
	if len(supported) > 0 {
		for _, name := range request.names() {
			if !slices.Contains(supported, name) {
				return ErrClaimNotSupported
			}
		}
	}
	return nil
}

// checkStateOrNonce takes 1 to maxStateBytes characters of the base64url alphabet.
func checkStateOrNonce(refused error, value string) error {
	if value == "" || len(value) > maxStateBytes {
		return fmt.Errorf("%w: not 1 to %d characters", refused, maxStateBytes)
	}
	for _, c := range []byte(value) {
		if !isBase64URL(c) {
			return fmt.Errorf("%w: a character outside A-Z a-z 0-9 - _", refused)
		}
	}
	return nil
}

// checkVerifier takes a code_verifier as RFC 7636 section 4.1 has it: 43 to 128 unreserved characters.
func checkVerifier(verifier string) error {
	if len(verifier) < minVerifierBytes || len(verifier) > maxVerifierBytes {
		return fmt.Errorf("%w: not %d to %d characters", ErrCodeVerifier, minVerifierBytes, maxVerifierBytes)
	}
	for _, c := range []byte(verifier) {
		if !isBase64URL(c) && c != '.' && c != '~' {
			return fmt.Errorf("%w: a character that is not unreserved", ErrCodeVerifier)
		}
	}
	return nil
}

func isBase64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// claimsRequest is what the relying party reads of the claims parameter (OIDC Core 5.5): the claims asked for in the
// ID token and at the userinfo endpoint, and which of them are essential.
type claimsRequest struct {
	idToken, userinfo map[string]bool
}

// names are the claims asked for, in either member.
func (r claimsRequest) names() []string {
	names := slices.Collect(maps.Keys(r.idToken))
	return append(names, slices.Collect(maps.Keys(r.userinfo))...)
}

// parseClaimsRequest reads a claims parameter. Each claim is null or an object whose essential, if present, is a
// boolean (OIDC Core 5.5.1); value and values are the IDP's to judge. Members other than id_token and userinfo are
// ignored, as OIDC Core 5.5 has it. openid.AuthorizationQuery holds the parameter to its size and shape bounds.
func parseClaimsRequest(raw json.RawMessage) (claimsRequest, error) {
	var request claimsRequest
	if len(raw) == 0 {
		return request, nil
	}
	if len(raw) > openid.MaxClaimsBytes {
		return request, fmt.Errorf("%w: larger than %d bytes", ErrClaimsRequest, openid.MaxClaimsBytes)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return request, fmt.Errorf("%w: not a JSON object", ErrClaimsRequest)
	}
	var err error
	if request.idToken, err = claimsMember(members["id_token"]); err != nil {
		return request, fmt.Errorf("%w: id_token: %w", ErrClaimsRequest, err)
	}
	if request.userinfo, err = claimsMember(members["userinfo"]); err != nil {
		return request, fmt.Errorf("%w: userinfo: %w", ErrClaimsRequest, err)
	}
	return request, nil
}

// claimsMember maps each claim of an id_token or userinfo member to whether it is essential.
func claimsMember(raw json.RawMessage) (map[string]bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(raw, &claims); err != nil || claims == nil {
		return nil, errors.New("not an object")
	}
	essential := make(map[string]bool, len(claims))
	for name, value := range claims {
		if string(value) == "null" {
			essential[name] = false
			continue
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(value, &members); err != nil || members == nil {
			return nil, errors.New("a claim is neither null nor an object")
		}
		if raw, ok := members["essential"]; ok {
			var flag bool
			if err := json.Unmarshal(raw, &flag); err != nil {
				return nil, errors.New("essential is no boolean")
			}
			essential[name] = flag
		} else {
			essential[name] = false
		}
	}
	return essential, nil
}
