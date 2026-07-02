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
