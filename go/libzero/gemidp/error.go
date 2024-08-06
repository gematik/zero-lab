package gemidp

import (
	"encoding/json"
	"fmt"
	"io"
)

// gematik IDP-Dienst retusn an error in the following format:
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
