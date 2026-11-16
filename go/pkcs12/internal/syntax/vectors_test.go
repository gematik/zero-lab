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

package syntax_test

import (
	"errors"
	"testing"

	"github.com/gematik/zero-lab/go/pkcs12/internal/conformance"
	"github.com/gematik/zero-lab/go/pkcs12/internal/syntax"
)

// TestP12_041TheCheckAgreesWithTheSharedVectors: the OID, parameter, publicKey
// and nesting rules of P12-041 on the vectors rust/ti-pkcs12 runs too.
func TestP12_041TheCheckAgreesWithTheSharedVectors(t *testing.T) {
	check, _ := conformance.PrivateKeyInfoVectors(t)
	if len(check) == 0 {
		t.Fatal("no check vectors")
	}
	for _, v := range check {
		t.Run(v.ID, func(t *testing.T) {
			err := syntax.CheckPrivateKeyInfo(v.Input)
			switch {
			case v.Expect == "ok" && err != nil:
				t.Errorf("error = %v, want ok", err)
			case v.Expect == "malformed" && !errors.Is(err, syntax.ErrParse):
				t.Errorf("error = %v, want ErrParse", err)
			}
		})
	}
}
