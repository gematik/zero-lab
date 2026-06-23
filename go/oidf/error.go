package oidf

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

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
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.Description)
}

// parseErrorResponse decodes an RFC 6749 error from the HTTP response body. source is the IDP URL the body
// came from, used to flag a non-compliant response. If the IDP sent the description in camelCase
// ("errorDescription"), it is still surfaced in Description and a warning names the offending IDP.
func parseErrorResponse(body io.Reader, source string) error {
	var oidcErr Error
	if err := json.NewDecoder(body).Decode(&oidcErr); err != nil {
		return fmt.Errorf("unable to decode error: %w", err)
	}
	if oidcErr.Description == "" && oidcErr.BadDescription != "" {
		oidcErr.Description = oidcErr.BadDescription
		slog.Warn("IDP returned error_description in camelCase (RFC 6749 expects snake_case)",
			"idp", source, "error", oidcErr.ErrorCode, "error_description", oidcErr.Description)
	}
	return &oidcErr
}
