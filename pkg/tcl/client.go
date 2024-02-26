package tcl

import (
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type TrustClient struct {
	regBaseURL string
	httpClient http.Client
	clientKey  jwk.Key
}

func NewClient(baseURL string, clientKey jwk.Key) (*TrustClient, error) {
	return &TrustClient{
		regBaseURL: baseURL,
		httpClient: http.Client{},
		clientKey:  clientKey,
	}, nil
}
