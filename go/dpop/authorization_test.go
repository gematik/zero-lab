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
	"errors"
	"net/http"
	"testing"
)

// Section 7.1, Figure 12: credentials = "DPoP" 1*SP token68; the scheme is case-insensitive
// (RFC 9110 Section 11.1).
func TestRFC9449_7_1_DPoPCredentialsAreParsed(t *testing.T) {
	for _, value := range []string{
		"DPoP " + rfcAccessToken,
		"dpop " + rfcAccessToken,
		"DPOP   " + rfcAccessToken,
	} {
		h := http.Header{}
		h.Set("Authorization", value)
		token, err := AccessToken(h)
		if err != nil || token != rfcAccessToken {
			t.Errorf("%q: %q, %v", value, token, err)
		}
	}
}

func TestRFC9449_7_1_MalformedCredentialsAreInvalidRequest(t *testing.T) {
	for _, values := range [][]string{
		{"Bearer " + rfcAccessToken},
		{"DPoP"},
		{"DPoP "},
		{"DPoP a b"},
		{"DPoPx " + rfcAccessToken},
		{"DPoP " + rfcAccessToken, "DPoP " + rfcAccessToken},
	} {
		h := http.Header{"Authorization": values}
		_, err := AccessToken(h)
		requireRefusedCode(t, err, CodeInvalidRequest)
	}
}

// Section 7.1, Figure 15: no credentials at all is a refusal without error code, which the
// resource server answers with a bare challenge.
func TestRFC9449_7_1_MissingCredentialsHaveNoErrorCode(t *testing.T) {
	_, err := AccessToken(http.Header{})
	requireRefused(t, err, "", "no access token")
}

func requireRefusedCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("got %v, want code %q", err, code)
	}
}
