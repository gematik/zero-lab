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
	"net/http"
	"regexp"
)

// Shared request-validation helpers, used across the authorization-server endpoints so the same input is
// checked the same way everywhere (no per-handler divergence).

// RFC 7636: the code_verifier is 43–128 characters from the unreserved set; the S256 code_challenge is the
// 43-character base64url (no padding) SHA-256 of the verifier.
var (
	codeVerifierRe  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	codeChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

func validateCodeVerifier(v string) *Error {
	if !codeVerifierRe.MatchString(v) {
		return oauthErr(http.StatusBadRequest, "invalid_grant", "code_verifier must be 43-128 unreserved characters (RFC 7636)")
	}
	return nil
}

func validateCodeChallenge(c string) *Error {
	if !codeChallengeRe.MatchString(c) {
		return oauthErr(http.StatusBadRequest, "invalid_request", "code_challenge must be a 43-character base64url S256 hash (RFC 7636)")
	}
	return nil
}
