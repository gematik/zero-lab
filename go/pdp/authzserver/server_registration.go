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

package authzserver

import (
	"net/http"
)

// RegistrationEndpoint is intentionally closed. Clients are provisioned out-of-band (operator config now,
// federation later), so dynamic client registration (RFC 7591) is not offered. The endpoint stays advertised
// in the metadata and returns a coherent OAuth error — the same shape as every other endpoint — rather than a
// bare 404, leaving a clean seam to enable gated registration later (swap this body, add storage).
func (s *Server) RegistrationEndpoint(w http.ResponseWriter, r *http.Request) error {
	return oauthErr(http.StatusForbidden, "access_denied",
		"dynamic client registration is not supported; clients are provisioned out-of-band")
}
