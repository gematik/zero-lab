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

package oidf

import (
	"log/slog"
	"net/http"
	"strings"
)

// gatedDomain holds the gematik environments that gate on x-authorization. The dot keeps
// xdev.gematik.solutions out.
const gatedDomain = ".dev.gematik.solutions"

type addAPIKeyTransport struct {
	t      http.RoundTripper
	apiKey string
}

// AddAPIKeyTransport wraps t so that https requests to hosts below dev.gematik.solutions carry apiKey as
// x-authorization. Without a key they go out unchanged and an error is logged. A nil t means
// http.DefaultTransport.
func AddAPIKeyTransport(t http.RoundTripper, apiKey string) http.RoundTripper {
	return &addAPIKeyTransport{t, apiKey}
}

func (adt *addAPIKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" && strings.HasSuffix(strings.ToLower(req.URL.Hostname()), gatedDomain) {
		if adt.apiKey != "" {
			// A RoundTripper must not change the request it was given.
			req = req.Clone(req.Context())
			req.Header.Set("x-authorization", adt.apiKey)
		} else {
			slog.Error("no federation API key configured", "host", req.URL.Host)
		}
	}
	if adt.t == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return adt.t.RoundTrip(req)
}
