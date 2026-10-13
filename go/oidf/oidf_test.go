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
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

const fedMasterJwksRef = `{
	"keys": [
	  {
		"kty": "EC",
		"crv": "P-256",
		"x": "cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs",
		"y": "XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw",
		"kid": "puk_fedmaster_sig",
		"use": "sig",
		"alg": "ES256"
	  }
	]
  }
`

// TestFederation fetches the IdP list, an entity statement, and its signed JWKS from a live OpenID
// Federation master. It is env-guarded (like gemidp/smcb_test.go): set OIDF_FEDMASTER_URL — e.g. the
// gematik reference federation master, https://app-ref.federationmaster.de — to run it; without it
// the test skips. The embedded fedMasterJwksRef is the reference master's public signing key.
func TestFederation(t *testing.T) {
	fedMasterURL := os.Getenv("OIDF_FEDMASTER_URL")
	if fedMasterURL == "" {
		t.Skip("OIDF_FEDMASTER_URL not set — skipping live OpenID Federation test")
	}

	jwks, err := jwk.ParseString(fedMasterJwksRef)
	if err != nil {
		t.Fatal(err)
	}

	fed, err := NewOpenidFederation(fedMasterURL, jwks)
	if err != nil {
		t.Fatal(err)
	}

	idps, err := fed.FetchIdpList()
	if err != nil {
		t.Fatal(err)
	}

	es, err := fed.FetchEntityStatement(idps[0].Issuer)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", es)

	idpJwks, err := fed.FetchSignedJwks(es)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", idpJwks)
}
