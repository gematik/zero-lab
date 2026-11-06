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

package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
	"github.com/gematik/zero-lab/go/pep/proxy"
)

// pdpBackendFromEnv builds the PDP backend (PEP_BACKEND=pdp): pep as a confidential client of the PDP. The
// private_key_jwt signing key is read from a file (PEP_CLIENT_SIGNING_KEY_PATH), never from an env value. client
// carries the requests to the PDP.
func pdpBackendFromEnv(publicURL string, client *http.Client) proxy.Backend {
	asIssuer := os.Getenv("PEP_AS_ISSUER")
	clientID := os.Getenv("PEP_CLIENT_ID")
	if asIssuer == "" || clientID == "" {
		log.Fatal("PEP_BACKEND=pdp requires PEP_AS_ISSUER and PEP_CLIENT_ID")
	}
	signingKey, err := loadJWKFile(os.Getenv("PEP_CLIENT_SIGNING_KEY_PATH"))
	if err != nil {
		log.Fatalf("PEP_CLIENT_SIGNING_KEY_PATH: %v", err)
	}
	redirect := os.Getenv("PEP_REDIRECT_URI")
	if redirect == "" {
		redirect = publicURL + "/oauth2/callback"
	}
	cfg := proxy.PDPConfig{
		ASIssuer:    asIssuer,
		ClientID:    clientID,
		SigningKey:  signingKey,
		RedirectURI: redirect,
		HTTPClient:  client,
	}
	if s := os.Getenv("PEP_SCOPES"); s != "" {
		cfg.Scopes = strings.Fields(s)
	}
	b, err := proxy.NewPDPBackend(cfg)
	if err != nil {
		log.Fatalf("pdp backend: %v", err)
	}
	return b
}

// loadJWKFile reads a single JWK (the client signing key) from a file.
func loadJWKFile(path string) (*jose.JSONWebKey, error) {
	if path == "" {
		return nil, errors.New("path is required")
	}
	data, err := os.ReadFile(path) //nolint:gosec // the path comes from PEP_CLIENT_SIGNING_KEY_PATH in the operator's environment, not a request
	if err != nil {
		return nil, err
	}
	return openid.ParseKey(data)
}
