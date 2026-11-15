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
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/url"
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
func textMember(members map[string]jsontext.Value, name string, most int) (value string, present bool, err error) {
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

// grantedScopes reads the scope of a token response, which openid.ParseTokenResponse held to space-separated
// scope-tokens of NQCHAR (RFC 6749 section 3.3); without one, the scopes asked for were granted (section 5.1).
func grantedScopes(scope string, asked []string) []string {
	if scope == "" {
		return slices.Clone(asked)
	}
	return strings.Split(scope, " ")
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
func parseClaimsRequest(raw jsontext.Value) (claimsRequest, error) {
	var request claimsRequest
	if len(raw) == 0 {
		return request, nil
	}
	if len(raw) > openid.MaxClaimsBytes {
		return request, fmt.Errorf("%w: larger than %d bytes", ErrClaimsRequest, openid.MaxClaimsBytes)
	}
	var members map[string]jsontext.Value
	if err := openid.UnmarshalObject(raw, openid.ClaimsDepth, openid.ClaimsMembers, &members); err != nil {
		return request, fmt.Errorf("%w: not a JSON object within bounds", ErrClaimsRequest)
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
func claimsMember(raw jsontext.Value) (map[string]bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var claims map[string]jsontext.Value
	if err := json.Unmarshal(raw, &claims); err != nil || claims == nil {
		return nil, errors.New("not an object")
	}
	essential := make(map[string]bool, len(claims))
	for name, value := range claims {
		if string(value) == "null" {
			essential[name] = false
			continue
		}
		var members map[string]jsontext.Value
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

// ErrRedirectURINotRegistered is a redirect URI that is not byte for byte one the relying party registered.
var ErrRedirectURINotRegistered = errors.New("redirect_uri not registered")

// checkRedirectURI takes a redirect URI equal to one of registered, compared as strings: no normalisation of case,
// percent-encoding or trailing slash, no prefix match (RFC 9700 section 4.1.3). The IDP compares it with the
// redirect_uris of the statement it fetched, so a URI the statement lacks would be refused there; refusing it here
// keeps a login's code from being sent where nobody registered.
func checkRedirectURI(uri string, registered []string) error {
	if uri == "" || !slices.Contains(registered, uri) {
		return ErrRedirectURINotRegistered
	}
	return nil
}

// ErrEntityIdentifier is an entity identifier, an IDP's issuer usually from a request's idp_iss, that is refused
// before anything is fetched at or about it.
var ErrEntityIdentifier = errors.New("entity identifier refused")

// checkEntityIdentifier takes an entity identifier (OpenID Federation 1.1 section 1.2) a fetch can be built from by
// appending a path: an https URL of at most maxEntityIdentifierBytes printable ASCII characters with a host name
// as isHost takes it and an optional port, without user info, query or fragment, without
// '.' or '..' segments, without '\' and without '%'. A '%' is refused outright rather than only before an encoded
// '/', '\', '?', '#' or '@': no issuer of the federation uses one, and so double encoding cannot slip through either.
// The admission compares it byte for byte with the IdP list, so nothing is normalised.
func checkEntityIdentifier(iss string) error {
	if iss == "" || len(iss) > maxEntityIdentifierBytes {
		return fmt.Errorf("%w: not 1 to %d characters", ErrEntityIdentifier, maxEntityIdentifierBytes)
	}
	for _, c := range []byte(iss) {
		if c <= 0x20 || c >= 0x7f || c == '%' || c == '\\' || c == '?' || c == '#' || c == '@' {
			return fmt.Errorf("%w: a character outside its grammar", ErrEntityIdentifier)
		}
	}
	rest, found := strings.CutPrefix(iss, "https://")
	if !found {
		return fmt.Errorf("%w: not https", ErrEntityIdentifier)
	}
	host, path, _ := strings.Cut(rest, "/")
	if !isHost(host) {
		return fmt.Errorf("%w: no host name in lowercase", ErrEntityIdentifier)
	}
	for segment := range strings.SplitSeq(path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("%w: a dot segment", ErrEntityIdentifier)
		}
	}
	return nil
}

// isHost reports whether host is a name of labels of lowercase letters, digits and inner hyphens, 1 to 63 characters
// each and separated by single dots (RFC 1123 section 2.1), which takes IPv4 addresses too, with an optional port of
// digits. A trailing dot, an empty label and upper case are refused: the host is compared as it stands.
func isHost(host string) bool {
	name, port, hasPort := strings.Cut(host, ":")
	if name == "" || hasPort && (port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "") {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// Bounds of a PAR response (RFC 9126 section 2.2).
const (
	maxRequestURIBytes = 512
	// maxPARLifetime bounds expires_in: a pushed request is used within seconds, and RFC 9126 section 2.2 names 60
	// as an example.
	maxPARLifetime = 600
)

// ErrPARResponse is a PAR response refused before its request_uri is used.
var ErrPARResponse = errors.New("PAR response refused")

// pushedAuthorizationResponse is a PAR response (RFC 9126 section 2.2).
type pushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

// parsePARResponse reads a PAR response with encoding/json/v2, members ignored that it does not name, and takes a
// request_uri of 1 to maxRequestURIBytes printable ASCII characters that is a urn: URI or an https URL with a host
// and neither user info nor fragment, and an expires_in of 1 to maxPARLifetime seconds. The request_uri goes into the
// authorization URL the browser is sent to, so nothing else may pass.
func parsePARResponse(body []byte) (pushedAuthorizationResponse, error) {
	var pushed pushedAuthorizationResponse
	if err := openid.UnmarshalObject(body, openid.ResponseDepth, openid.ResponseMembers, &pushed); err != nil {
		return pushed, fmt.Errorf("%w: %w", ErrPARResponse, err)
	}
	if err := checkRequestURI(pushed.RequestURI); err != nil {
		return pushed, err
	}
	if pushed.ExpiresIn < 1 || pushed.ExpiresIn > maxPARLifetime {
		return pushed, fmt.Errorf("%w: expires_in is not 1 to %d", ErrPARResponse, maxPARLifetime)
	}
	return pushed, nil
}

func checkRequestURI(uri string) error {
	if uri == "" || len(uri) > maxRequestURIBytes {
		return fmt.Errorf("%w: request_uri is not 1 to %d characters", ErrPARResponse, maxRequestURIBytes)
	}
	for _, c := range []byte(uri) {
		if c <= 0x20 || c >= 0x7f {
			return fmt.Errorf("%w: request_uri holds a character outside printable ASCII", ErrPARResponse)
		}
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%w: request_uri is no URI", ErrPARResponse)
	}
	switch {
	// The prefixes are compared as sent: url.Parse would lowercase a scheme in upper case.
	case strings.HasPrefix(uri, "urn:") && parsed.Opaque != "":
		return nil
	case strings.HasPrefix(uri, "https://") && parsed.Hostname() != "" && parsed.User == nil && !strings.Contains(uri, "#"):
		return nil
	}
	return fmt.Errorf("%w: request_uri is neither a urn: URI nor an https URL", ErrPARResponse)
}
