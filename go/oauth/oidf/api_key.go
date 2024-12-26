package oidf

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
)

type addApiKeyTransport struct {
	t http.RoundTripper
}

func AddApiKeyTransport(t http.RoundTripper) http.RoundTripper {
	return &addApiKeyTransport{t}
}

func (adt *addApiKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// see if domain ends with .dev.gematik.solutions
	// if so, add the api key
	if strings.HasSuffix(req.URL.Host, "dev.gematik.solutions") {
		apiKey := os.Getenv("API_KEY")
		if apiKey != "" {
			req.Header.Add("x-authorization", apiKey)
		} else {
			slog.Error("no API_KEY set", "url", req.URL)
		}
	}
	if adt.t == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return adt.t.RoundTrip(req)
}
