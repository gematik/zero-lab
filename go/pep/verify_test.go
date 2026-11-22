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

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/pep"
)

// RFC 9700 Section 4.10.2: a resource server refuses a token not meant for it, so a PEP without a resource is not
// built, and a token for another resource is refused.
func TestRFC9700_4_10_2_TheAudienceIsRequired(t *testing.T) {
	jwks, err := pep.ParseJWKSet([]byte(publicJWSKSet))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pep.NewBuilder().WithJWKSet(jwks).WithDPoPReplays(dpop.NewMemoryReplays(100, nil)).Build(); err == nil {
		t.Fatal("a PEP was built without a resource")
	}
	// createTestAccessToken issues a token with audience "https://example.com".
	token, err := createTestAccessToken([]byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	matchPEP, err := pep.NewBuilder().WithJWKSet(jwks).Resource("https://example.com").WithDPoPReplays(dpop.NewMemoryReplays(100, nil)).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := matchPEP.VerifyAccessToken(token); err != nil {
		t.Fatalf("a token for the resource was refused: %v", err)
	}
	otherPEP, err := pep.NewBuilder().WithJWKSet(jwks).Resource("https://other.example.com").WithDPoPReplays(dpop.NewMemoryReplays(100, nil)).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherPEP.VerifyAccessToken(token); err == nil {
		t.Fatal("a token for another resource was accepted")
	}
}
