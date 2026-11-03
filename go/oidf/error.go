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
	"encoding/json"
	"fmt"
	"io"
)

// Error is an OAuth 2.0 error response (RFC 6749 §5.2) with the members gematik's IDPs add to it.
type Error struct {
	Operation        string `json:"operation"`
	ErrorCode        string `json:"error"`
	Description      string `json:"error_description"`
	GematikTimestamp int64  `json:"gematik_timestamp,omitempty"`
	GematikUUID      string `json:"gematik_uuid,omitempty"`
	GematikCode      string `json:"gematik_code,omitempty"`
	// BadDescription captures error_description sent in camelCase ("errorDescription"), which some IDPs
	// return in violation of RFC 6749. parseErrorResponse folds it into Description.
	BadDescription string `json:"errorDescription,omitempty"`
}

func (e *Error) Error() string {
	s := fmt.Sprintf("%s: %s", e.ErrorCode, e.Description)
	if e.GematikCode != "" {
		s += fmt.Sprintf(" (gematik_code=%s)", e.GematikCode)
	}
	if e.GematikUUID != "" {
		s += fmt.Sprintf(" [gematik_uuid=%s]", e.GematikUUID)
	}
	return s
}

// parseErrorResponse decodes an RFC 6749 error from the HTTP response body. source is the IDP URL the body came from.
// A description sent in camelCase ("errorDescription") is still surfaced in Description. The body stays out of the error
// when it does not decode, since it comes from outside and may echo what the provider was sent.
func parseErrorResponse(body io.Reader, source string) error {
	raw, _ := io.ReadAll(io.LimitReader(body, 8192))
	var oidcErr Error
	if err := json.Unmarshal(raw, &oidcErr); err != nil {
		return fmt.Errorf("unable to decode error from %s: %w", source, err)
	}
	if oidcErr.Description == "" && oidcErr.BadDescription != "" {
		oidcErr.Description = oidcErr.BadDescription
	}
	return &oidcErr
}
