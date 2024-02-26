package oidf

import (
	"encoding/json"
	"fmt"
	"io"
)

type Error struct {
	Operation        string `json:"operation"`
	ErrorCode        string `json:"error"`
	Description      string `json:"error_description"`
	GematikTimestamp int64  `json:"gematik_timestamp,omitempty"`
	GematikUUID      string `json:"gematik_uuid,omitempty"`
	GematikCode      string `json:"gematik_code,omitempty"`
	// TODO: temporary
	BadDescription string `json:"errorDescription,omitempty"`
}

func (e *Error) Error() string {
	if e.BadDescription != "" {
		return fmt.Sprintf("%s: %s (errorDescription)", e.ErrorCode, e.BadDescription)
	}
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.Description)
}

// tries to parse the oath2 error from the body
func parseOauth2Error(body io.Reader) error {
	var oidcErr Error
	err := json.NewDecoder(body).Decode(&oidcErr)
	if err != nil {
		return fmt.Errorf("unable to decode error: %w", err)
	}
	return &oidcErr
}
