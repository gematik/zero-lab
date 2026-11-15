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

package openid

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// maxResponseBytes bounds what a provider can make a relying party read.
const maxResponseBytes = 1 << 20

// AuthorizationQuery is the query of an authorization request with PKCE, or the form of a pushed one. The login's
// scopes replace the configured ones when it has any. It refuses what would change meaning on the wire: a scope or
// acr value that is empty or holds a space or a character outside NQCHAR (RFC 6749 §3.3), and a claims parameter
// that is no JSON object or larger than [MaxClaimsBytes] (OIDC Core 5.5).
func AuthorizationQuery(clientID, redirectURI string, scopes []string, login Login) (url.Values, error) {
	if len(login.Scopes) > 0 {
		scopes = login.Scopes
	}
	if err := checkTokens(ErrScope, scopes, maxScopes, true); err != nil {
		return nil, err
	}
	if err := checkTokens(ErrACRValue, login.ACRValues, maxACRValues, false); err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("client_id", clientID)
	query.Set("redirect_uri", login.RedirectFor(redirectURI))
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", login.State)
	query.Set("nonce", login.Nonce)
	query.Set("code_challenge", S256Challenge(login.Verifier))
	query.Set("code_challenge_method", CodeChallengeMethodS256)
	if len(login.ACRValues) > 0 {
		query.Set("acr_values", strings.Join(login.ACRValues, " "))
	}
	if len(login.Claims) > 0 {
		if err := checkClaimsParameter(login.Claims); err != nil {
			return nil, err
		}
		query.Set("claims", string(login.Claims))
	}
	return query, nil
}

// Response is a provider's answer, read whole and within [maxResponseBytes].
type Response struct {
	Status      int
	ContentType string
	Body        []byte
}

// ErrResponseContentType is a response whose body is not declared as JSON.
var ErrResponseContentType = errors.New("response is not declared as JSON")

// CheckJSON refuses a response whose Content-Type is not application/json, alone or with charset=utf-8 (RFC 8259
// section 8.1 has JSON in UTF-8), before its body is parsed (servers.md rule 28).
func (r *Response) CheckJSON() error {
	mediaType, params, err := mime.ParseMediaType(r.ContentType)
	// mime takes a parameter repeated with the same value; one parameter is all there may be.
	if err != nil || mediaType != "application/json" || strings.Count(r.ContentType, ";") > 1 {
		return ErrResponseContentType
	}
	for name, value := range params {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return ErrResponseContentType
		}
	}
	return nil
}

// PostForm posts a form to a provider's endpoint.
func PostForm(ctx context.Context, client *http.Client, endpoint string, form url.Values) (*Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json, */*")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("response larger than %d bytes", maxResponseBytes)
	}
	return &Response{Status: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body}, nil
}

// ParseTokenResponse reads a token response (RFC 6749 section 5.1) by its exact member names and ignores members it
// does not know, as section 5.1 asks. Before anything is used:
//   - token_type is Bearer or DPoP, compared without case (section 7.1);
//   - access_token and refresh_token, when present, are VSCHAR within maxBearerBytes (Appendix A.12, A.17);
//   - id_token, when present, is at most [MaxIDTokenBytes] in compact form: three or five dot-separated base64url
//     parts, a JWS or a JWE (RFC 7515 section 7.1, RFC 7516 section 7.1), before any JOSE parser sees it;
//   - scope is space-separated NQCHAR tokens (section 3.3);
//   - expires_in is a non-negative integer. Entra ID writes it as a string of digits, which is tolerated.
func ParseTokenResponse(body []byte) (*TokenResponse, error) {
	var wire struct {
		TokenType    jsontext.Value `json:"token_type"`
		AccessToken  jsontext.Value `json:"access_token"`
		RefreshToken jsontext.Value `json:"refresh_token"`
		IDToken      jsontext.Value `json:"id_token"`
		Scope        jsontext.Value `json:"scope"`
		ExpiresIn    jsontext.Value `json:"expires_in"`
	}
	if err := UnmarshalObject(body, ResponseDepth, ResponseMembers, &wire); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenResponse, err)
	}
	refuse := func(reason string) (*TokenResponse, error) {
		return nil, fmt.Errorf("%w: %s", ErrTokenResponse, reason)
	}
	var response TokenResponse
	var ok bool
	if response.TokenType, ok = stringValue(wire.TokenType); !ok ||
		!strings.EqualFold(response.TokenType, "Bearer") && !strings.EqualFold(response.TokenType, "DPoP") {
		return refuse("token_type is neither Bearer nor DPoP")
	}
	for _, member := range []struct {
		name   string
		raw    jsontext.Value
		target *string
	}{{"access_token", wire.AccessToken, &response.AccessToken}, {"refresh_token", wire.RefreshToken, &response.RefreshToken}} {
		value, ok := stringValue(member.raw)
		if !ok || isPresent(member.raw) && (value == "" || len(value) > maxBearerBytes || !isVSChars(value)) {
			return refuse(member.name + " is not VSCHAR within bounds")
		}
		*member.target = value
	}
	if response.IDTokenRaw, ok = stringValue(wire.IDToken); !ok || isPresent(wire.IDToken) && !isCompactJOSE(response.IDTokenRaw) {
		return refuse(fmt.Sprintf("id_token is no compact JWS or JWE of at most %d bytes", MaxIDTokenBytes))
	}
	if response.Scope, ok = stringValue(wire.Scope); !ok || isPresent(wire.Scope) && !isScope(response.Scope) {
		return refuse("scope is not space-separated NQCHAR")
	}
	var err error
	if response.ExpiresIn, err = expiresIn(wire.ExpiresIn); err != nil {
		return refuse("expires_in is no non-negative integer")
	}
	return &response, nil
}

// isPresent reports whether a member is there and not null.
func isPresent(raw jsontext.Value) bool {
	return len(raw) > 0 && raw.Kind() != 'n'
}

// isCompactJOSE reports whether token is within MaxIDTokenBytes and has the compact form of a JWS or a JWE. Only the
// first part, the protected header, may not be empty: a JWE agreed by ECDH-ES directly has no encrypted key.
func isCompactJOSE(token string) bool {
	if len(token) > MaxIDTokenBytes {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 && len(parts) != 5 || parts[0] == "" {
		return false
	}
	for _, part := range parts {
		for _, c := range []byte(part) {
			if !isBase64URL(c) {
				return false
			}
		}
	}
	return true
}

func isBase64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// isScope reports whether scope is scope-tokens of NQCHAR separated by single spaces (RFC 6749 section 3.3).
func isScope(scope string) bool {
	if len(scope) > maxScopeBytes {
		return false
	}
	for token := range strings.SplitSeq(scope, " ") {
		if token == "" {
			return false
		}
		for _, c := range []byte(token) {
			if c != 0x21 && (c < 0x23 || c > 0x7e || c == 0x5c) {
				return false
			}
		}
	}
	return true
}

// expiresIn reads expires_in as a JSON integer or a string of decimal digits; absent or null is zero.
func expiresIn(raw jsontext.Value) (int, error) {
	if !isPresent(raw) {
		return 0, nil
	}
	var digits string
	if err := json.Unmarshal(raw, &digits); err != nil {
		digits = string(raw)
	}
	if digits == "" || len(digits) > 10 || strings.Trim(digits, "0123456789") != "" {
		return 0, errors.New("no non-negative integer")
	}
	return strconv.Atoi(digits)
}
