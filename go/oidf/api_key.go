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
	"os"
	"strings"
)

type addAPIKeyTransport struct {
	t http.RoundTripper
}

// AddAPIKeyTransport wraps t so that requests to hosts ending in dev.gematik.solutions carry the
// API_KEY environment variable as x-authorization, which those gematik environments gate on. Without
// API_KEY the request goes out unchanged and an error is logged. A nil t means http.DefaultTransport.
func AddAPIKeyTransport(t http.RoundTripper) http.RoundTripper {
	return &addAPIKeyTransport{t}
}

func (adt *addAPIKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// see if domain ends with .dev.gematik.solutions
	// if so, add the api key
	if strings.HasSuffix(req.URL.Host, "dev.gematik.solutions") {
		apiKey := os.Getenv("API_KEY")
		if apiKey != "" {
			req.Header.Add("x-authorization", apiKey)
		} else {
			slog.Error("no API_KEY set", "host", req.URL.Host)
		}
	}
	if adt.t == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return adt.t.RoundTrip(req)
}
