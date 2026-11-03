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

package oid

import (
	"crypto/x509"
	"testing"
)

func TestParseAcceptsOnlyTheCanonicalDottedForm(t *testing.T) {
	for _, text := range []string{"", ".", "1", "1.", ".1.2", "1..2", "3.1", "1.40", "1.2.276.0.76.4.030", "01.2", "+1.2", "1.2 ", "1.2.x"} {
		if id, err := Parse(text); err == nil {
			t.Errorf("Parse(%q) = %s", text, id)
		}
	}
	for _, text := range []string{"0.4.0.2231.3.0", "1.2.276.0.76.4.30", "2.25.340282366920938463463374607431768211455"} {
		id, err := Parse(text)
		if err != nil || id.String() != text {
			t.Errorf("Parse(%q) = %s, %v", text, id, err)
		}
	}
}

func TestMustParsePanicsOnAnInvalidIdentifier(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	MustParse("1.2.x")
}

func TestLookupFindsEveryIdentifierByItsBinaryForm(t *testing.T) {
	for _, info := range All() {
		parsed, err := x509.ParseOID(info.OID.String())
		if err != nil {
			t.Fatalf("%s: %v", info.Reference, err)
		}
		found, ok := Lookup(parsed)
		if !ok || found.Reference != info.Reference {
			t.Errorf("%s: found %q", info.Reference, found.Reference)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"1.2.276.0.76.4.30", "1.2.276.0.76.4.030", "", "2.999.1", "1.2."} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		id, err := Parse(text)
		if err != nil {
			return
		}
		if id.String() != text {
			t.Errorf("%q reads as %s", text, id)
		}
		again, err := Parse(id.String())
		if err != nil || !again.Equal(id) {
			t.Errorf("%q does not survive a round trip: %v", text, err)
		}
	})
}
