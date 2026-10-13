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

package gemidp

import (
	"encoding/json"
	"fmt"
	"io"
)

// gematik IDP-Dienst returns an error in the following format:
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
	HttpCode         int    `json:"-"`
	ErrorCode        string `json:"error"`
	GematikErrorText string `json:"gematik_error_text"`
	GematikTimestamp int64  `json:"gematik_timestamp"`
	GematikUUID      string `json:"gematik_uuid"`
	GematikCode      string `json:"gematik_code"`
}

func (e *Error) Error() string {
	if e.HttpCode != 0 {
		return fmt.Sprintf("%d %s: %s (%s)", e.HttpCode, e.ErrorCode, e.GematikErrorText, e.GematikCode)
	} else {
		return fmt.Sprintf("%s: %s (%s)", e.ErrorCode, e.GematikErrorText, e.GematikCode)
	}
}

// tries to parse the oath2 error from the reader, taken from the HTTP response body
func parseErrorResponse(httpCode int, body io.Reader) error {
	var oidcErr Error
	err := json.NewDecoder(body).Decode(&oidcErr)
	if err != nil {
		return fmt.Errorf("unable to decode error: %w", err)
	}
	oidcErr.HttpCode = httpCode
	return &oidcErr
}
