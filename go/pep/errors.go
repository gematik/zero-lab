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

package pep

import "fmt"

type Error struct {
	HttpStatus  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s (code=%s)", e.Description, e.Code)
}

var ErrForbiddenHeadersInRequest = Error{
	HttpStatus:  400,
	Code:        "forbidden_headers_in_request",
	Description: "Request contains forbidden headers",
}

var ErrNoAuthorizationHeader = Error{
	HttpStatus:  401,
	Code:        "no_authorization_header",
	Description: "No Authorization header in request",
}

var ErrInvalidAuthorizationHeader = Error{
	HttpStatus:  400,
	Code:        "invalid_authorization_header",
	Description: "Invalid Authorization header in request",
}

func ErrorAccessDeinied(description string) Error {
	return Error{
		HttpStatus:  403,
		Code:        "access_denied",
		Description: description,
	}
}

var ErrSessionRequired = Error{
	HttpStatus:  401,
	Code:        "session_required",
	Description: "no valid session cookie",
}

var ErrMissingAccessTokenDPoPBinding = Error{
	HttpStatus:  400,
	Code:        "missing_access_token_dpop_binding",
	Description: "Access token is missing DPoP binding (cnf.jkt)",
}

var ErrInvalidAccessTokenDPoPBinding = Error{
	HttpStatus:  400,
	Code:        "invalid_access_token_dpop_binding",
	Description: "Key thumbprint in DPoP proof does not match access token",
}
