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

package pkcs12_test

import (
	"testing"

	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/internal/conformance"
)

// TestConformance decodes the spec/pkcs12 corpus. Cases of profile modern
// must meet their expectation; cases of profile legacy, which package legacy
// tests, must fail cleanly instead of decoding to something wrong.
func TestConformance(t *testing.T) {
	for _, c := range conformance.Corpus(t) {
		t.Run(c.ID+"/"+c.Encoding, func(t *testing.T) {
			bags, err := pkcs12.Decode(c.Data, c.Password)
			if c.Profile == "modern" {
				conformance.Check(t, c, bags, err)
				return
			}
			switch code := conformance.Code(err); code {
			case "malformed", "unsupported_algorithm":
			default:
				t.Errorf("legacy case: code %s (%v), want malformed or unsupported_algorithm", code, err)
			}
		})
	}
}
