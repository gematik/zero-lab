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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"slices"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// TestEntityStatementHook checks that a registered hook injects values into the served entity statement,
// that repeated signings do not accumulate, and that the relying party's base statement is untouched.
func TestEntityStatementHook(t *testing.T) {
	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks := &Jwks{Keys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: prk.Public(), KeyID: "sign-kid", Algorithm: "ES256"}}}}

	rp := &RelyingParty{
		cfg:           &RelyingPartyConfig{FedMasterURL: "https://fedmaster.example"},
		sigPrivateKey: prk,
		signKid:       "sign-kid",
		entityStatement: &EntityStatement{
			Issuer:  "https://rp.example",
			Subject: "https://rp.example",
			Jwks:    jwks,
			Metadata: &Metadata{
				OpenidRelyingParty: &OpenIDRelyingPartyMetadata{
					RedirectURIs: []string{"https://rp.example/cb"},
				},
			},
		},
	}

	const injected = "https://product.example/as-cb"
	rp.AddEntityStatementHook(func(es *EntityStatement) {
		orp := es.Metadata.OpenidRelyingParty
		orp.RedirectURIs = append(orp.RedirectURIs, injected)
	})

	servedRedirects := func() []string {
		signed, err := rp.SignEntityStatement()
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Metadata struct {
				OpenidRelyingParty struct {
					RedirectURIs []string `json:"redirect_uris"`
				} `json:"openid_relying_party"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(unverifiedPayload(t, signed), &claims); err != nil {
			t.Fatal(err)
		}
		return claims.Metadata.OpenidRelyingParty.RedirectURIs
	}

	first := servedRedirects()
	if !slices.Contains(first, injected) {
		t.Fatalf("hook redirect not in served entity statement: %v", first)
	}
	if second := servedRedirects(); len(second) != len(first) {
		t.Errorf("redirect_uris accumulated across signings: %d then %d", len(first), len(second))
	}
	if base := rp.entityStatement.Metadata.OpenidRelyingParty.RedirectURIs; len(base) != 1 {
		t.Errorf("base entity statement mutated by hook: %v", base)
	}
}
