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

package egress

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ErrPlainHTTP is an outbound request over plain http for data that does not prove itself (servers.md rule 30).
var ErrPlainHTTP = errors.New("egress: plain http is only for data that proves itself by its signature")

// selfVerifying marks a request context whose answer the caller verifies by its signature.
type selfVerifying struct{}

// SelfVerifying marks requests made with the returned context as fetching data that proves itself by its
// signature: OCSP responses, CRLs and the TSL with its signature (gemSpec_TSL A_21175 publishes them over plain
// http). Only such requests leave the client of [NewClient] over http.
//
// A library outside this module that fetches such data over a client the host hands it takes the marking as a
// function, a field or option of type func(context.Context) context.Context, which the host fills with
// SelfVerifying: the library then needs no import of this package, nor this package one of the library.
func SelfVerifying(ctx context.Context) context.Context {
	return context.WithValue(ctx, selfVerifying{}, true)
}

// NewClient is the egress client (servers.md rule 30): an HTTP client for servers on the internet, verified
// under the web profile against the host system's roots, the client a host gives a library for its internet
// endpoints (TLSV-001). It goes out over https, and over plain http only for a request marked [SelfVerifying];
// a forward proxy configured in the environment is used as net/http's default does. It fails when the system's
// roots cannot be read. timeout bounds each request; opts are the verifier's, its RevocationTimeout bounding
// the revocation fetches.
func NewClient(timeout time.Duration, opts Options) (*http.Client, error) {
	transport, err := NewTransport(opts)
	if err != nil {
		return nil, err
	}
	transport.Proxy = egressProxy
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

// NewTransport is the transport of [NewClient] without its rule for plain http and without a forward proxy:
// for a peer of the deployment that the host configured itself, such as an upstream behind a gateway, which may
// be reached over http. Its https connections are verified under the web profile.
func NewTransport(opts Options) (*http.Transport, error) {
	check, err := SystemWebCheck()
	if err != nil {
		return nil, err
	}
	// OCSP responses and CRLs prove themselves by their signatures, so their own transport needs no
	// profile of its own; verifying it under the web profile would ask for the responder's status in turn.
	fetch := NewHTTPFetcher(&http.Client{Timeout: opts.timeout()})
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("egress: http.DefaultTransport is a %T, not an *http.Transport", http.DefaultTransport)
	}
	transport := base.Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = NewWebVerifier(check, fetch, opts).ClientConfig()
	return transport, nil
}

// egressProxy is the Proxy of the egress transport, which net/http asks before every request, a redirected one
// included: https goes out, http only for a request marked [SelfVerifying], and nothing else. It lives in the Proxy
// hook rather than in a wrapping RoundTripper so that the transport stays an *http.Transport whose clones (a
// library adding a client certificate) keep the rule.
func egressProxy(r *http.Request) (*url.URL, error) {
	switch r.URL.Scheme {
	case "https":
	case "http":
		if marked, _ := r.Context().Value(selfVerifying{}).(bool); !marked {
			return nil, fmt.Errorf("%w: %s", ErrPlainHTTP, r.URL.Redacted())
		}
	default:
		return nil, fmt.Errorf("egress: %q is no scheme of an outbound request", r.URL.Scheme)
	}
	return http.ProxyFromEnvironment(r)
}
