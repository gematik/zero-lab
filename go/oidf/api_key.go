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
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// gatedDomain holds the gematik environments that gate on x-authorization. The dot keeps
// xdev.gematik.solutions out.
const gatedDomain = ".dev.gematik.solutions"

// ErrAPIKeyRequired is a federation master in the gated development federation configured without its API key.
// Every fetch from it would be refused, so the start is (servers.md rule 17).
var ErrAPIKeyRequired = errors.New("the federation master is gated and no API key is configured")

// isGated reports whether u is an https URL the API key is sent with.
func isGated(u *url.URL) bool {
	return u.Scheme == "https" && strings.HasSuffix(strings.ToLower(u.Hostname()), gatedDomain)
}

// checkAPIKey refuses a gated master without a key. A master URL that does not parse is left to the fetch, which
// refuses it.
func checkAPIKey(fedMasterURL, apiKey string) error {
	parsed, err := url.Parse(fedMasterURL)
	if err != nil || apiKey != "" || !isGated(parsed) {
		return nil
	}
	return ErrAPIKeyRequired
}

type addAPIKeyTransport struct {
	t      http.RoundTripper
	apiKey string
}

// AddAPIKeyTransport wraps t so that https requests to hosts below dev.gematik.solutions carry apiKey as
// x-authorization. Without a key they go out unchanged; a federation refuses a gated master without one at
// construction (see [ErrAPIKeyRequired]). A nil t means http.DefaultTransport.
func AddAPIKeyTransport(t http.RoundTripper, apiKey string) http.RoundTripper {
	return &addAPIKeyTransport{t, apiKey}
}

func (adt *addAPIKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if adt.apiKey != "" && isGated(req.URL) {
		// A RoundTripper must not change the request it was given.
		req = req.Clone(req.Context())
		req.Header.Set("x-authorization", adt.apiKey)
	}
	if adt.t == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return adt.t.RoundTrip(req)
}
