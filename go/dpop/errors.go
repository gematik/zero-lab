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
		HttpStatus:  http.StatusUnauthorized,
		Code:        "authorization_required",
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
