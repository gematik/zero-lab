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

package providers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
)

// TLSV-001: the program chooses how providers are reached; the client it puts in the Env carries the
// requests of an oidc entry, whose own configuration cannot name one.
func TestTLSV001TheProgramsClientCarriesTheProviders(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "k", Algorithm: "ES256", Use: "sig"}}}
	var server *httptest.Server
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/j" {
			_ = json.NewEncoder(w).Encode(keys)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/a",
			"token_endpoint":         server.URL + "/t",
			"jwks_uri":               server.URL + "/j",
		})
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)

	decode := func(v any) error {
		*v.(*[]openid.Config) = []openid.Config{{
			Issuer: server.URL, ClientID: "client", ClientSecret: openid.NewSecretString("secret"), RedirectURI: "https://rp.example/cb",
		}}
		return nil
	}
	if _, err := OIDC(decode, Env{}); err == nil {
		t.Fatal("reached without the program's client, under roots that do not hold the provider's")
	}
	built, err := OIDC(decode, Env{HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Providers) != 1 || built.Providers[0].Issuer != server.URL {
		t.Errorf("%+v", built.Providers)
	}
}
