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

package idpd

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"slices"
)

// Error is an error response of the gematik IDP-Dienst, which has the following format:
//
//	{
//		 "error":"invalid_request",
//		 "gematik_error_text":
//		 "client_id ist ungültig",
//		 "gematik_timestamp":1713603116,
//		 "gematik_uuid":"c0e2a77c-dfae-4b93-9baf-f170683962cb",
//		 "gematik_code":"2012"
//	}
type Error struct {
	HTTPCode         int    `json:"-"`
	ErrorCode        string `json:"error"`
	GematikErrorText string `json:"gematik_error_text"`
	GematikTimestamp int64  `json:"gematik_timestamp"`
	GematikUUID      string `json:"gematik_uuid"`
	GematikCode      string `json:"gematik_code"`
}

// Error names the status, an error code RFC 6749 registers and a gematik_code of digits, the form gemSpec_IDP_Dienst
// gives them. Another error, gematik_error_text and anything else are the IDP-Dienst's text, which reaches the fields
// but not the error text: error text ends up in logs (servers.md rule 14).
func (e *Error) Error() string {
	text := "IDP-Dienst refused"
	if e.HTTPCode != 0 {
		text += fmt.Sprintf(" with status %d", e.HTTPCode)
	}
	if slices.Contains(registeredOAuthErrors, e.ErrorCode) {
		text += ", error " + e.ErrorCode
	}
	if isGematikCode(e.GematikCode) {
		text += ", gematik_code " + e.GematikCode
	}
	return text
}

// registeredOAuthErrors are the error codes of RFC 6749 Sections 4.1.2.1 and 5.2: words this package knows, so they
// may stand in an error text where anything else the IDP-Dienst sends may not.
var registeredOAuthErrors = []string{
	"invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type", "invalid_scope",
	"server_error", "temporarily_unavailable", "invalid_client", "invalid_grant", "unsupported_grant_type",
}

// isGematikCode takes the gematik_code of gemSpec_IDP_Dienst, a few digits.
func isGematikCode(code string) bool {
	if code == "" || len(code) > 8 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// reasonError refuses an answer of the IDP-Dienst by a fixed reason. A decoder's message quotes member names and
// values; the decoder's error stays reachable through errors.Is and errors.As, so a caller can still tell why.
type reasonError struct {
	reason string
	err    error
}

func (e *reasonError) Error() string { return e.reason }

func (e *reasonError) Unwrap() error { return e.err }

// tries to parse the oath2 error from the reader, taken from the HTTP response body
func parseErrorResponse(httpCode int, body io.Reader) error {
	var oidcErr Error
	err := json.UnmarshalRead(io.LimitReader(body, maxIDPResponseBytes), &oidcErr)
	if err != nil {
		return fmt.Errorf("IDP-Dienst refused with status %d; its error does not decode", httpCode)
	}
	oidcErr.HTTPCode = httpCode
	return &oidcErr
}
