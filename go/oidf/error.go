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
	s := fmt.Sprintf("%s: %s", e.ErrorCode, e.Description)
	if e.GematikCode != "" {
		s += fmt.Sprintf(" (gematik_code=%s)", e.GematikCode)
	}
	if e.GematikUUID != "" {
		s += fmt.Sprintf(" [gematik_uuid=%s]", e.GematikUUID)
	}
	return s
}

// parseErrorResponse decodes an RFC 6749 error from the HTTP response body. source is the IDP URL the body
// came from, used to flag a non-compliant response. If the IDP sent the description in camelCase
// ("errorDescription"), it is still surfaced in Description and a warning names the offending IDP. The raw
// body is logged at debug so terse IDP errors (e.g. a generic "400 BAD_REQUEST") can still be inspected.
func parseErrorResponse(body io.Reader, source string) error {
	raw, _ := io.ReadAll(io.LimitReader(body, 8192))
	var oidcErr Error
	if err := json.Unmarshal(raw, &oidcErr); err != nil {
		return fmt.Errorf("unable to decode error from %s (body %q): %w", source, string(raw), err)
	}
	if oidcErr.Description == "" && oidcErr.BadDescription != "" {
		oidcErr.Description = oidcErr.BadDescription
		slog.Warn("IDP returned error_description in camelCase (RFC 6749 expects snake_case)",
			"idp", source, "error", oidcErr.ErrorCode, "error_description", oidcErr.Description)
	}
	slog.Debug("IDP error response", "idp", source, "body", string(raw))
	return &oidcErr
}
