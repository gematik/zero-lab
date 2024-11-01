package util

import "net/http"

type addHttpHeaderTransport struct {
	t     http.RoundTripper
	name  string
	value string
}

// Deprecated: do not use commons/util package
func AddHttpHeaderTransport(t http.RoundTripper, name, value string) http.RoundTripper {
	return &addHttpHeaderTransport{t, name, value}
}

func AddUserAgentTransport(t http.RoundTripper, userAgent string) http.RoundTripper {
	return AddHttpHeaderTransport(t, "User-Agent", userAgent)
}

func (adt *addHttpHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add(adt.name, adt.value)
	if adt.t == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return adt.t.RoundTrip(req)
}
