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
	// Some IDPs return description in camelCase instead of snake_case
	BadDescription string `json:"errorDescription,omitempty"`
}

func (e *Error) Error() string {
	if e.BadDescription != "" {
		return fmt.Sprintf("%s: %s (wrong camelCase response)", e.ErrorCode, e.BadDescription)
	}
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.Description)
}

// tries to parse the oath2 error from the reader, taken from the HTTP response body
func parseErrorResponse(body io.Reader) error {
	var oidcErr Error
	err := json.NewDecoder(body).Decode(&oidcErr)
	if err != nil {
		return fmt.Errorf("unable to decode error: %w", err)
	}
	return &oidcErr
}
