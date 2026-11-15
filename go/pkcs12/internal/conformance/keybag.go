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

package conformance

import (
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/gematik/zero-lab/go/pkcs12/internal/syntax"
)

// KeyBagFile builds a PKCS#12 file without MAC and without encryption whose
// only safe holds one keyBag with value as its bagValue. No encoder writes a
// plain keyBag, so the tests of its checks build it by hand.
func KeyBagFile(t testing.TB, value []byte) []byte {
	t.Helper()
	dataContentInfo := func(b *cryptobyte.Builder, content []byte) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(syntax.OIDData)
			b.AddASN1(syntax.TagContext0Explicit, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(content)
			})
		})
	}
	var safe cryptobyte.Builder
	safe.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(syntax.OIDKeyBag)
			b.AddASN1(syntax.TagContext0Explicit, func(b *cryptobyte.Builder) {
				b.AddBytes(value)
			})
		})
	})
	var authSafe cryptobyte.Builder
	authSafe.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		dataContentInfo(b, safe.BytesOrPanic())
	})
	var pfx cryptobyte.Builder
	pfx.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(3)
		dataContentInfo(b, authSafe.BytesOrPanic())
	})
	data, err := pfx.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
