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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gematik/zero-lab/go/tipki"
)

// Fetcher is what a check asks of the network: an OCSP responder or a CRL host. The host performs it with
// its own client, proxy and timeouts; this package opens no connection itself. An error is "did not
// answer", which the checks treat as no source.
type Fetcher interface {
	// OCSP POSTs the DER request to the responder at url and returns its DER response.
	OCSP(ctx context.Context, url string, request []byte) ([]byte, error)
	// CRL GETs the DER CRL at url.
	CRL(ctx context.Context, url string) ([]byte, error)
}

// ErrOffline is what [Offline] answers.
var ErrOffline = errors.New("titls: offline: no revocation source is reachable")

// Offline is a [Fetcher] that never answers: every revocation source is down.
type Offline struct{}

// OCSP implements [Fetcher].
func (Offline) OCSP(context.Context, string, []byte) ([]byte, error) { return nil, ErrOffline }

// CRL implements [Fetcher].
func (Offline) CRL(context.Context, string) ([]byte, error) { return nil, ErrOffline }

// The body limits of [HTTPFetcher]: an OCSP response is a few kilobytes even with a delegate's
// certificate, while a public CA's CRL can run to megabytes.
const (
	DefaultMaxOCSPBytes = 64 << 10
	DefaultMaxCRLBytes  = 16 << 20
)

// HTTPFetcher is a [Fetcher] over the host's *http.Client. OCSP and CRLs are published over plain HTTP;
// the answers prove themselves by their signatures. Only http and https URLs are followed.
type HTTPFetcher struct {
	// Client carries every request; nil fails every request, as no default client is used.
	Client *http.Client
	// MaxOCSPBytes and MaxCRLBytes bound a response body; zero means the defaults.
	MaxOCSPBytes int64
	MaxCRLBytes  int64
}

// NewHTTPFetcher is the fetcher over client with the default limits.
func NewHTTPFetcher(client *http.Client) *HTTPFetcher {
	return &HTTPFetcher{Client: client}
}

// OCSP implements [Fetcher].
func (f *HTTPFetcher) OCSP(ctx context.Context, url string, request []byte) ([]byte, error) {
	limit := f.MaxOCSPBytes
	if limit <= 0 {
		limit = DefaultMaxOCSPBytes
	}
	req, err := f.request(ctx, http.MethodPost, url, request)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	return f.do(req, limit)
}

// CRL implements [Fetcher].
func (f *HTTPFetcher) CRL(ctx context.Context, url string) ([]byte, error) {
	limit := f.MaxCRLBytes
	if limit <= 0 {
		limit = DefaultMaxCRLBytes
	}
	req, err := f.request(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return f.do(req, limit)
}

func (f *HTTPFetcher) request(ctx context.Context, method, target string, body []byte) (*http.Request, error) {
	if f.Client == nil {
		return nil, errors.New("titls: no HTTP client")
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("titls: %q: %w", target, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("titls: %q: only http and https are fetched", target)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	return http.NewRequestWithContext(ctx, method, target, reader)
}

func (f *HTTPFetcher) do(req *http.Request, limit int64) ([]byte, error) {
	response, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("titls: %s answered %d", req.URL, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("titls: %s answered more than %d bytes", req.URL, limit)
	}
	return body, nil
}

// OCSPTransport carries tipki's OCSP queries over f, so the ti profile's responder ([tipki.OCSPChecker])
// and the web profile reach the network the same way.
func OCSPTransport(f Fetcher) tipki.OCSPTransport { return ocspTransport{f} }

type ocspTransport struct{ fetch Fetcher }

// Post implements [tipki.OCSPTransport]; the fetcher sets the OCSP media types itself.
func (t ocspTransport) Post(ctx context.Context, url, _, _ string, body []byte) ([]byte, error) {
	return t.fetch.OCSP(ctx, url, body)
}
