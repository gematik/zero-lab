package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type DiscoveryDocument struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	RevocationEndpoint               string   `json:"revocation_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

func FetchDiscoveryDocument(url string) (*DiscoveryDocument, error) {
	resp, err := http.Get(string(url))
	if err != nil {
		return nil, fmt.Errorf("unable to get discovery document: %w", err)
	}
	defer resp.Body.Close()

	var doc DiscoveryDocument
	err = json.NewDecoder(resp.Body).Decode(&doc)
	if err != nil {
		return nil, fmt.Errorf("unable to decode discovery document: %w", err)
	}

	return &doc, nil
}
