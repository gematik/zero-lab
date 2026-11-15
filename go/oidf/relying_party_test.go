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
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// unverifiedPayload reads the claims of a compact JWS, for a test that has already got what it needs from the signer.
func unverifiedPayload(t *testing.T, signed []byte) []byte {
	t.Helper()
	parts := strings.Split(string(signed), ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %s", signed)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestNewAtALiveFederationMaster(t *testing.T) {
	fedMasterURL := os.Getenv("OIDF_FEDMASTER_URL")
	if fedMasterURL == "" {
		t.Skip("OIDF_FEDMASTER_URL not set — skipping (New fetches a live federation master)")
	}
	fedMasterJwk, err := NewJwkFromJSON(`{
		"kty": "EC",
		"crv": "P-256",
		"x":   "cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs",
		"y":   "XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw",
		"kid": "puk_fedmaster_sig",
		"use": "sig",
		"alg": "ES256"
	}`)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &RelyingPartyConfig{
		Subject:          "https://example.com",
		FedMasterURL:     fedMasterURL,
		FedMasterJWK:     fedMasterJwk,
		RelyingParty:     testRelyingPartyMetadata(),
		FederationEntity: testFederationEntity(),
		Documents:        NewMemoryDocuments(16, nil),
	}

	es, err := New(t.Context(), cfg, newTestKeys(t))
	if err != nil {
		t.Fatal(err)
	}

	signed, err := es.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}

	var claims struct {
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(unverifiedPayload(t, signed), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Metadata == nil {
		t.Fatal("metadata not found")
	}

	t.Log(claims.Metadata)
}

func TestBuildMetadataFillsTheDefaultsAConfigOmits(t *testing.T) {
	cfg := &RelyingPartyConfig{RelyingParty: RelyingPartyMetadata{ClientName: "c", RedirectURIs: []string{"https://rp/cb"}}}
	md := cfg.buildMetadata().OpenidRelyingParty
	if md.TokenEndpointAuthMethod != "self_signed_tls_client_auth" || md.IDTokenEncryptedResponseEnc != "A256GCM" {
		t.Errorf("defaults not applied: %+v", md)
	}
}

// Internal invariant: a relying party not built by New serves no statement, so it registers no redirect URI, scope or
// ID token version a login could be held to, and every login is refused; it does not sign either.
func TestServerRule17_ARelyingPartyNotBuiltByNewRefusesEveryLogin(t *testing.T) {
	rp := literalRelyingParty(t, newTestKey(t))
	registered := rp.registered()
	if len(registered.redirectURIs) != 0 || registered.scope != "" || len(registered.idTokenVersions) != 0 {
		t.Errorf("registered %+v", registered)
	}
	if err := checkRedirectURI("https://rp.example/cb", registered.redirectURIs); !errors.Is(err, ErrRedirectURINotRegistered) {
		t.Errorf("redirect URI: %v", err)
	}
	if err := checkLogin(validLogin(), []string{"openid"}, registered.scope, nil); !errors.Is(err, ErrScopeNotRegistered) {
		t.Errorf("scope: %v", err)
	}
	if err := (&RelyingParty{}).Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "not built by New") {
		t.Errorf("Refresh: %v", err)
	}
}
