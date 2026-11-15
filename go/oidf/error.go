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
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/gematik/zero-lab/go/openid"
)

// maxGematikMemberBytes bounds the members gematik's IDPs add to an error response.
const maxGematikMemberBytes = 64

// Error is an OAuth 2.0 error response (RFC 6749 §5.2) with the members gematik's IDPs add to it. Each text member
// holds NQSCHAR only, within its bound, or is empty: what came otherwise was dropped. The text is data for the host,
// to log as a field, never to put into HTML or a header.
type Error struct {
	Operation        string `json:"operation"`
	ErrorCode        string `json:"error"`
	Description      string `json:"error_description"`
	GematikTimestamp int64  `json:"gematik_timestamp,omitzero"`
	GematikUUID      string `json:"gematik_uuid,omitempty"`
	GematikCode      string `json:"gematik_code,omitempty"`
}

// Error puts the members into its text: parseErrorResponse let only bounded printable ASCII through, which cannot
// break the log line it ends up in.
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

// parseErrorResponse reads the error response of an IDP or a federation member (servers.md rule 28): it has to be
// declared as JSON, and its error as [openid.ParseErrorResponse] holds it, or the response is refused with
// [openid.ErrErrorResponse] and the status alone. A description sent in camelCase ("errorDescription"), which some
// IDPs return in violation of RFC 6749, stands in for a missing error_description. The gematik members are dropped
// when they are not NQSCHAR within maxGematikMemberBytes, like the description. Nothing of the body reaches the error
// otherwise, since it comes from outside and may echo what the provider was sent.
func parseErrorResponse(response *openid.Response) error {
	refused := func(err error) error {
		return fmt.Errorf("status %d: %w", response.Status, err)
	}
	if err := response.CheckJSON(); err != nil {
		return refused(fmt.Errorf("%w: %w", openid.ErrErrorResponse, err))
	}
	standard, err := openid.ParseErrorResponse(response.Body)
	if err != nil {
		return refused(err)
	}
	var gematik struct {
		Operation      jsontext.Value `json:"operation"`
		Timestamp      jsontext.Value `json:"gematik_timestamp"`
		UUID           jsontext.Value `json:"gematik_uuid"`
		Code           jsontext.Value `json:"gematik_code"`
		BadDescription jsontext.Value `json:"errorDescription"`
	}
	// openid.ParseErrorResponse checked the body's bounds already.
	if err := json.Unmarshal(response.Body, &gematik); err != nil {
		return refused(fmt.Errorf("%w: a member is not of its type", openid.ErrErrorResponse))
	}
	oidcErr := &Error{
		ErrorCode:   standard.Code,
		Description: standard.Description,
		Operation:   errorText(gematik.Operation, maxGematikMemberBytes),
		GematikUUID: errorText(gematik.UUID, maxGematikMemberBytes),
		GematikCode: errorText(gematik.Code, maxGematikMemberBytes),
	}
	if oidcErr.Description == "" {
		oidcErr.Description = errorText(gematik.BadDescription, openid.MaxErrorDescriptionBytes)
	}
	if json.Unmarshal(gematik.Timestamp, &oidcErr.GematikTimestamp) != nil || oidcErr.GematikTimestamp < 0 {
		oidcErr.GematikTimestamp = 0
	}
	return oidcErr
}

// errorText is the member raw if it is a string of NQSCHAR within most bytes, and "" otherwise.
func errorText(raw jsontext.Value, most int) string {
	var value string
	if json.Unmarshal(raw, &value) != nil || !openid.IsErrorText(value, most) {
		return ""
	}
	return value
}
