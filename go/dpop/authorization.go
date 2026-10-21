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

package dpop

import (
	"net/http"
	"strings"
)

// AccessToken returns the access token of a request's DPoP-scheme Authorization header
// (Section 7.1): exactly one header, the scheme DPoP compared case-insensitively (RFC 9110
// Section 11.1), one or more spaces, and the token in token68 syntax (Figure 12).
//
// A request without Authorization is refused with an [*Error] without code, which
// [Verifier.WriteChallenge] answers with a bare challenge (Figure 15). A Bearer token is a
// malformed request here: a resource server that also accepts Bearer tokens decides that
// before calling AccessToken, and must not accept a DPoP-bound token as Bearer (Section 7.2).
func AccessToken(header http.Header) (string, error) {
	values := header.Values("Authorization")
	switch len(values) {
	case 0:
		return "", &Error{Description: "no access token"}
	case 1:
	default:
		return "", &Error{Code: CodeInvalidRequest, Description: "more than one Authorization header"}
	}
	scheme, rest, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, Scheme) {
		return "", &Error{Code: CodeInvalidRequest, Description: "Authorization is not of the DPoP scheme"}
	}
	token := strings.TrimLeft(rest, " ")
	if !isToken68(token) {
		return "", &Error{Code: CodeInvalidRequest, Description: "DPoP credentials are not a token68 value"}
	}
	return token, nil
}
