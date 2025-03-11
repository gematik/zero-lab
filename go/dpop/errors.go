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

var (
	ErrMissingHeader = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "missing_header",
		Description: "Missing DPoP header",
	}

	ErrInvalidToken = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_token",
		Description: "Invalid token",
	}

	ErrUseDPoPNonce = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "use_dpop_nonce",
		Description: "DPoP nonce is required",
	}

	ErrInvalidDPoPKeyBinding = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_token",
		Description: "Invalid DPoP key binding",
	}

	ErrMultipleMethods = DPoPError{
		HttpStatus:  http.StatusBadRequest,
		Code:        "invalid_request",
		Description: "Multiple methods used to include access token",
	}
)
