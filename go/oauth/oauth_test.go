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

package oauth

import (
	"encoding/base64"
	"testing"
)

// RFC 7636 Appendix B.
func TestS256ChallengeMatchesRFC7636AppendixB(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := S256Challenge(verifier); got != challenge {
		t.Errorf("S256Challenge = %q, want %q", got, challenge)
	}
}

func TestGenerateVerifierIsFreshAndCarries32Octets(t *testing.T) {
	first, second := GenerateVerifier(), GenerateVerifier()
	if first == second {
		t.Error("two verifiers are equal")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 32 {
		t.Errorf("verifier carries %d octets, want 32", len(decoded))
	}
}
