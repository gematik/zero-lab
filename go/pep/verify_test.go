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

package pep_test

import (
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/pep"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// TestVerifyAccessToken_AudienceOptional proves the PEP can be reused both as a guard before a
// resource server (audience enforced when Resource is set) and inside an authorization server
// (audience unrestricted when no Resource is configured).
func TestVerifyAccessToken_AudienceOptional(t *testing.T) {
	jwks, err := jwk.Parse([]byte(publicJWSKSet))
	if err != nil {
		t.Fatal(err)
	}
	// createTestAccessToken issues a token with audience "https://example.com".
	token, err := createTestAccessToken([]byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}

	// No resource configured (authorization-server use): audience is not restricted.
	asPEP, err := pep.NewBuilder().WithJWKSet(jwks).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := asPEP.VerifyAccessToken(token); err != nil {
		t.Fatalf("verify without resource should succeed: %v", err)
	}

	// Resource matching the token audience: accepted.
	matchPEP, err := pep.NewBuilder().WithJWKSet(jwks).Resource("https://example.com").Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := matchPEP.VerifyAccessToken(token); err != nil {
		t.Fatalf("verify with matching resource should succeed: %v", err)
	}

	// Resource guarding a different resource server: audience enforced, token rejected.
	otherPEP, err := pep.NewBuilder().WithJWKSet(jwks).Resource("https://other.example.com").Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherPEP.VerifyAccessToken(token); err == nil {
		t.Fatal("verify with mismatched resource should fail")
	}
}
