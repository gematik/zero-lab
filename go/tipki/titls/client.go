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

package titls

import (
	"fmt"
	"net/http"
	"time"
)

// NewWebHTTPClient is an HTTP client for servers on the internet, verified under the web profile against
// the host system's roots: the client a host gives a library for its internet endpoints (TLSV-001). It
// fails when the system's roots cannot be read. timeout bounds each request, the revocation fetches
// included; opts are the verifier's.
func NewWebHTTPClient(timeout time.Duration, opts Options) (*http.Client, error) {
	check, err := SystemWebCheck()
	if err != nil {
		return nil, err
	}
	// OCSP responses and CRLs prove themselves by their signatures, so their own transport needs no
	// profile of its own; verifying it under the web profile would ask for the responder's status in turn.
	fetch := NewHTTPFetcher(&http.Client{Timeout: timeout})
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("titls: http.DefaultTransport is a %T, not an *http.Transport", http.DefaultTransport)
	}
	transport := base.Clone()
	transport.TLSClientConfig = NewWebVerifier(check, fetch, opts).ClientConfig()
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}
