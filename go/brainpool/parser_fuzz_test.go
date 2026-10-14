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

package brainpool

import "testing"

// These fuzz targets assert that the hand-written DER parsers never panic on
// malformed input (they may return errors). Run e.g.:
//
//	go test -run x -fuzz FuzzParseCertificate -fuzztime 30s

func FuzzParseCertificate(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseCertificate(data)
	})
}

func FuzzParseECPrivateKey(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseECPrivateKey(data)
	})
}

func FuzzParsePKCS8PrivateKey(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParsePKCS8PrivateKey(data)
	})
}
