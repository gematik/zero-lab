package dpop

import "fmt"

type DPoPError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (e *DPoPError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
}

var (
	ErrInvalidToken = DPoPError{
		ErrorCode:        "invalid_token",
		ErrorDescription: "Invalid token",
	}

	ErrUseDPoPNonce = DPoPError{
		ErrorCode:        "use_dpop_nonce",
		ErrorDescription: "Authorization server requires nonce in DPoP proof",
	}

	ErrInvalidDPoPKeyBinding = DPoPError{
		ErrorCode:        "invalid_token",
		ErrorDescription: "Invalid DPoP key binding",
	}

	ErrMultipleMethods = DPoPError{
		ErrorCode:        "invalid_request",
		ErrorDescription: "Multiple methods used to include access token",
	}
)
