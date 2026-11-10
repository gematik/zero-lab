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

package titls

import (
	"crypto/x509"
	"encoding/binary"
	"slices"
	"testing"
)

// FuzzWebCheck feeds any bytes as the chain a server presents, up to four certificates each behind a
// two-byte big-endian length, to the web profile with the corpus's root and no revocation source.
// Invariants: it never panics, and whatever comes out valid carries revocation_unavailable and is not
// reused (TLSV-044, TLSV-050). The seeds are corpus chains.
func FuzzWebCheck(f *testing.F) {
	frame := func(certs ...[]byte) []byte {
		var data []byte
		for _, der := range certs {
			data = binary.BigEndian.AppendUint16(data, uint16(len(der)))
			data = append(data, der...)
		}
		return data
	}
	f.Add(frame(corpusDER(f, "web-p256.pem"), corpusDER(f, "web-ca.pem")))
	f.Add(frame(corpusDER(f, "web-under-weak-ca.pem"), corpusDER(f, "web-ca-1024.pem")))
	f.Add(frame(corpusDER(f, "ti-good.pem"), corpusDER(f, "ti-ca.pem"), corpusDER(f, "ti-root.pem")))
	f.Add([]byte{})
	check := NewWebCheck([]*x509.Certificate{corpusCert(f, "web-root.pem")})
	f.Fuzz(func(t *testing.T, data []byte) {
		var chain [][]byte
		for len(chain) < 4 && len(data) >= 2 {
			length := min(int(binary.BigEndian.Uint16(data)), len(data)-2)
			chain = append(chain, data[2:2+length])
			data = data[2+length:]
		}
		verdict := check.Verify(t.Context(), chain, "www.web.test", nil, at, Offline{})
		if verdict.Valid() && (!slices.Contains(verdict.Warnings, WarningRevocationUnavailable) || !verdict.ReusableUntil.IsZero()) {
			t.Fatalf("valid without a revocation source, as if it had one: %+v", verdict)
		}
		if verdict.Code == "" {
			t.Fatal("a verdict without a code")
		}
	})
}
