package dpop

import (
	"fmt"
	"net/http"
)

type DPoPError struct {
	HttpStatus  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e DPoPError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func (e DPoPError) WriteResponse(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(e.HttpStatus)
	writer.Write([]byte(fmt.Sprintf(`{"error": "%s", "error_description": "%s"}`, e.Code, e.Description)))
}

var (
	ErrMissingHeader = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_dpop_proof",
		Description: "Missing DPoP header",
	}

	ErrUseDPoPNonce = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_dpop_proof",
		Description: "DPoP nonce is required",
	}

	ErrInvalidDPoPKeyBinding = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_dpop_proof",
		Description: "Invalid DPoP key binding",
	}

	ErrMultipleAuthorizationMethods = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_request",
		Description: "Multiple methods used to include access token",
	}

	ErrMissingAuthorizationHeader = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_request",
		Description: "Missing authorization header",
	}

	ErrInvalidAuthorizationHeader = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_request",
		Description: "Invalid authorization header",
	}

	ErrMissingAccessTokenHash = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_dpop_proof",
		Description: "Missing access token hash",
	}

	ErrInvalidAccessTokenHash = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_dpop_proof",
		Description: "Invalid access token hash",
	}
)
