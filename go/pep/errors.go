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

// Error is a denial handed to Context.Deny: the HTTP status and challenge, and an OAuth 2.0 error response
// body (RFC 6749 Section 5.2). An empty Code sends the status and challenge without a body.
type Error struct {
	HTTPStatus  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	// WWWAuthenticate is the challenge to send with the denial, if any (RFC 9449 Section 7.1).
	WWWAuthenticate string `json:"-"`
	// DPoPNonce is the nonce the client's next proof has to carry, if any (RFC 9449 Section 9).
	DPoPNonce string `json:"-"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s (code=%s)", e.Description, e.Code)
}

// ErrForbiddenHeadersInRequest denies a request carrying headers the resource does not accept (status 400).
var ErrForbiddenHeadersInRequest = Error{
	HTTPStatus:  400,
	Code:        "forbidden_headers_in_request",
	Description: "Request contains forbidden headers",
}

// ErrNoAuthorizationHeader denies a request without an Authorization header (status 401).
var ErrNoAuthorizationHeader = Error{
	HTTPStatus:  401,
	Code:        "no_authorization_header",
	Description: "No Authorization header in request",
}

// ErrInvalidAuthorizationHeader denies a request whose Authorization headers hold no credentials of the
// expected scheme (status 400).
var ErrInvalidAuthorizationHeader = Error{
	HTTPStatus:  400,
	Code:        "invalid_authorization_header",
	Description: "Invalid Authorization header in request",
}

// ErrorAccessDeinied is a 403 access_denied denial; the description reaches the client as error_description,
// so it must not carry internals.
func ErrorAccessDeinied(description string) Error {
	return Error{
		HTTPStatus:  403,
		Code:        "access_denied",
		Description: description,
	}
}

// ErrSessionRequired denies a request without a valid session cookie (status 401).
var ErrSessionRequired = Error{
	HTTPStatus:  401,
	Code:        "session_required",
	Description: "no valid session cookie",
}
