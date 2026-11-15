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
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
)

// Bounds of the request values a login may carry. They travel in a URL or a PAR form, where providers cap the size,
// and nothing a login needs comes near them.
const (
	// MaxClaimsBytes bounds the claims request parameter.
	MaxClaimsBytes = 4096
	// maxClaimsDepth bounds the nesting of objects and arrays in the claims parameter; OIDC Core 5.5 needs three.
	maxClaimsDepth = 5
	// maxClaimsMembers bounds the members of all objects of the claims parameter together.
	maxClaimsMembers = 64
	// maxScopes and maxACRValues bound how many values a request names.
	maxScopes    = 16
	maxACRValues = 8
	// maxTokenBytes bounds one scope or acr value.
	maxTokenBytes = 128
)

// The request values AuthorizationQuery refuses. Each error names the field, never the value: what is refused may
// come from the caller's client and must not reach a log.
var (
	ErrClaimsParameter = errors.New("claims parameter refused")
	ErrScope           = errors.New("scope refused")
	ErrACRValue        = errors.New("acr value refused")
)

// checkClaimsParameter takes a JSON object (OIDC Core 5.5) of valid UTF-8, within the bounds above and without a
// member named twice in any object, since providers would resolve a duplicate each their own way. It walks the
// tokens before anything is decoded and refuses rather than repairs.
func checkClaimsParameter(claims []byte) error {
	if len(claims) > MaxClaimsBytes {
		return fmt.Errorf("%w: larger than %d bytes", ErrClaimsParameter, MaxClaimsBytes)
	}
	if err := checkJSONObject(claims, maxClaimsDepth, maxClaimsMembers); err != nil {
		return fmt.Errorf("%w: %w", ErrClaimsParameter, err)
	}
	return nil
}

// ErrJSON is a JSON text refused before it is decoded.
var ErrJSON = errors.New("JSON refused")

// UnmarshalObject decodes a JSON object from outside into target with encoding/json/v2, after CheckJSONObject let it
// through. v2 refuses invalid UTF-8 and a member named twice, which v1 resolves silently by keeping the last, and
// matches member names exactly, where v1 would fill an "iss" field from "ISS" (servers.md rule 28). Members target
// does not name are ignored, as OAuth responses require (RFC 6749 section 5.1). The error names neither a member nor
// a value: the decoder's own messages quote both.
func UnmarshalObject(data []byte, depth, members int, target any) error {
	if err := CheckJSONObject(data, depth, members); err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%w: a member is not of its type", ErrJSON)
	}
	return nil
}

// CheckJSONObject takes one JSON object, nested at most depth deep, with at most members members in all its objects
// together, of valid UTF-8 and without a member named twice in any object (servers.md rule 28). It reads the tokens
// before anything is decoded, so the bounds hold before anything grows with the input.
func CheckJSONObject(data []byte, depth, members int) error {
	if err := checkJSONObject(data, depth, members); err != nil {
		return fmt.Errorf("%w: %w", ErrJSON, err)
	}
	return nil
}

// checkJSONObject walks the tokens with jsontext, whose decoder refuses invalid UTF-8 and duplicate names by
// default. Its errors quote the input, so they are replaced by a reason.
func checkJSONObject(data []byte, maxDepth, maxMembers int) error {
	decoder := jsontext.NewDecoder(bytes.NewReader(data))
	if decoder.PeekKind() != '{' {
		return errors.New("not a JSON object")
	}
	members := 0
	for {
		// Inside an object, a name comes at every even position.
		if kind, length := decoder.StackIndex(decoder.StackDepth()); kind == '{' && length%2 == 0 && decoder.PeekKind() != '}' {
			if members++; members > maxMembers {
				return fmt.Errorf("more than %d members", maxMembers)
			}
		}
		if _, err := decoder.ReadToken(); err != nil {
			if errors.Is(err, jsontext.ErrDuplicateName) {
				return errors.New("a member named twice")
			}
			return errors.New("not JSON")
		}
		if decoder.StackDepth() > maxDepth {
			return fmt.Errorf("nested deeper than %d", maxDepth)
		}
		if decoder.StackDepth() == 0 {
			break
		}
	}
	if _, err := decoder.ReadToken(); !errors.Is(err, io.EOF) {
		return errors.New("data after the object")
	}
	return nil
}

// checkTokens holds each value to RFC 6749's scope-token = 1*NQCHAR, which space-separated acr_values share: a
// space inside one value would split it into two on the provider's side. refused is the sentinel of the field, most
// bounds how many values there may be, and unique refuses a value named twice.
func checkTokens(refused error, values []string, most int, unique bool) error {
	if len(values) > most {
		return fmt.Errorf("%w: more than %d values", refused, most)
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("%w: empty", refused)
		}
		if len(value) > maxTokenBytes {
			return fmt.Errorf("%w: longer than %d bytes", refused, maxTokenBytes)
		}
		if unique && seen[value] {
			return fmt.Errorf("%w: a value named twice", refused)
		}
		seen[value] = true
		for _, r := range value {
			if r != 0x21 && (r < 0x23 || r > 0x7e || r == 0x5c) {
				return fmt.Errorf("%w: a character outside NQCHAR", refused)
			}
		}
	}
	return nil
}

// Bounds of the values a login exchanges with a provider beyond its request.
const (
	// maxAuthorizationCodeBytes bounds the code a callback hands over; providers issue far shorter ones.
	maxAuthorizationCodeBytes = 2048
	// maxErrorCodeBytes and maxErrorDescriptionBytes bound the text of an error response (RFC 6749 section 5.2).
	maxErrorCodeBytes        = 64
	maxErrorDescriptionBytes = 256
	// MaxIDTokenBytes bounds the ID token of a token response, signed or signed and encrypted.
	MaxIDTokenBytes = 16 << 10
	// maxBearerBytes bounds an access or refresh token; a provider's own token format decides their length.
	maxBearerBytes = 32 << 10
	// maxScopeBytes bounds the scope of a token response.
	maxScopeBytes = 1024
	// ResponseDepth and ResponseMembers bound the JSON of a provider's response, which holds a handful of flat members.
	ResponseDepth   = 8
	ResponseMembers = 256
)

// The values of a login's exchange refused. Each error names the field, never the value.
var (
	ErrAuthorizationCode = errors.New("authorization code refused")
	ErrErrorResponse     = errors.New("error response refused")
	ErrTokenResponse     = errors.New("token response refused")
)

// CheckAuthorizationCode takes the code of a callback as RFC 6749 Appendix A.11 has it, 1*VSCHAR (%x20-7E), within
// maxAuthorizationCodeBytes. CR, LF and NUL lie outside VSCHAR, so the code cannot split the form it is posted in.
func CheckAuthorizationCode(code string) error {
	if code == "" || len(code) > maxAuthorizationCodeBytes {
		return fmt.Errorf("%w: not 1 to %d characters", ErrAuthorizationCode, maxAuthorizationCodeBytes)
	}
	if !isVSChars(code) {
		return fmt.Errorf("%w: a character outside VSCHAR", ErrAuthorizationCode)
	}
	return nil
}

func isVSChars(value string) bool {
	for _, c := range []byte(value) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// IsErrorText reports whether value is 1 to most characters of NQSCHAR (%x20-21 / %x23-5B / %x5D-7E), the grammar
// RFC 6749 Appendix A.7 and A.8 give error and error_description: printable ASCII without '"' and '\'.
func IsErrorText(value string, most int) bool {
	if value == "" || len(value) > most {
		return false
	}
	for _, c := range []byte(value) {
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// ParseErrorResponse reads an OAuth error response (RFC 6749 section 5.2). Its error has to be NQSCHAR of at most
// maxErrorCodeBytes, or the whole response is refused. An error_description outside its grammar or longer than
// maxErrorDescriptionBytes is dropped rather than refusing the response: the request failed either way, and the code
// still says why. error_uri is never read, since a host could otherwise be made to link to wherever a provider says.
func ParseErrorResponse(body []byte) (*Error, error) {
	var wire struct {
		Code        jsontext.Value `json:"error"`
		Description jsontext.Value `json:"error_description"`
	}
	if err := UnmarshalObject(body, ResponseDepth, ResponseMembers, &wire); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrErrorResponse, err)
	}
	code, ok := stringValue(wire.Code)
	if !ok || !IsErrorText(code, maxErrorCodeBytes) {
		return nil, fmt.Errorf("%w: error is not 1 to %d characters of NQSCHAR", ErrErrorResponse, maxErrorCodeBytes)
	}
	description, ok := stringValue(wire.Description)
	if !ok || !IsErrorText(description, maxErrorDescriptionBytes) {
		description = ""
	}
	return &Error{Code: code, Description: description}, nil
}

// stringValue reads a member that has to be a string when present; absent or null is "".
func stringValue(raw jsontext.Value) (string, bool) {
	var value string
	if len(raw) == 0 {
		return "", true
	}
	return value, json.Unmarshal(raw, &value) == nil
}
