package common

import (
	"fmt"
	"net/http"
)

// NewHTTPClient returns an HTTP client with proxy support (HTTP_PROXY, HTTPS_PROXY,
// NO_PROXY) and a User-Agent header on every request.
func NewHTTPClient() *http.Client {
	return ClientWithTransport(&http.Transport{
		Proxy: http.ProxyFromEnvironment,
	})
}

func ClientWithTransport(base http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: &userAgentTransport{base: base},
	}
}

type userAgentTransport struct {
	base http.RoundTripper
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", fmt.Sprintf("ti/%s", Version))
	return t.base.RoundTrip(r)
}
