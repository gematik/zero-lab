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
	"encoding/json"
	"errors"
	"fmt"
)

// MaxClaimsBytes bounds the claims request parameter a login may carry; it travels in a URL or a PAR form, where
// providers cap the size.
const MaxClaimsBytes = 4096

// The request values AuthorizationQuery refuses. Each error names the field, never the value: what is refused may
// come from the caller's client and must not reach a log.
var (
	ErrClaimsParameter = errors.New("claims parameter refused")
	ErrScope           = errors.New("scope refused")
	ErrACRValue        = errors.New("acr value refused")
)

// checkClaimsParameter takes a JSON object of at most MaxClaimsBytes (OIDC Core 5.5) and refuses anything else; it
// repairs nothing.
func checkClaimsParameter(claims json.RawMessage) error {
	if len(claims) > MaxClaimsBytes {
		return fmt.Errorf("%w: larger than %d bytes", ErrClaimsParameter, MaxClaimsBytes)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(claims, &members); err != nil || members == nil {
		return fmt.Errorf("%w: not a JSON object", ErrClaimsParameter)
	}
	return nil
}

// checkTokens holds each value to RFC 6749's scope-token = 1*NQCHAR, which space-separated acr_values share: a
// space inside one value would split it into two on the provider's side. refused is the sentinel of the field.
func checkTokens(refused error, values []string) error {
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("%w: empty", refused)
		}
		for _, r := range value {
			if r != 0x21 && (r < 0x23 || r > 0x7e || r == 0x5c) {
				return fmt.Errorf("%w: a character outside NQCHAR", refused)
			}
		}
	}
	return nil
}
