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

package proxy

import (
	"net/http"
	"testing"

	"github.com/gematik/zero-lab/go/dpop"
)

func TestBffSignerProof(t *testing.T) {
	priv, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(jwkJSON) == 0 {
		t.Fatal("expected serialized key")
	}
	if _, err := parseSessionDPoPKey(jwkJSON); err != nil {
		t.Fatalf("parseSessionDPoPKey: %v", err)
	}

	req, _ := http.NewRequest("GET", "https://api.example/protected", nil)
	proof, err := (bffSigner{}).dpopProof(req, "the-access-token", priv)
	if err != nil {
		t.Fatalf("dpopProof: %v", err)
	}
	parsed, err := dpop.Parse(proof)
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	if parsed.HttpMethod != "GET" || parsed.HttpURI != "https://api.example/protected" {
		t.Errorf("htm/htu = %s %s", parsed.HttpMethod, parsed.HttpURI)
	}
	ath, _ := dpop.CalculateAccessTokenHash("the-access-token")
	if parsed.AccessTokenHash != ath {
		t.Errorf("ath = %q, want %q", parsed.AccessTokenHash, ath)
	}
}
