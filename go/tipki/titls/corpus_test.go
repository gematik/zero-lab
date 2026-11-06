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
	"slices"
	"testing"
	"time"
)

// TLSV-020, TLSV-021, TLSV-022, TLSV-023, TLSV-024, TLSV-040, TLSV-041, TLSV-042, TLSV-043, TLSV-044 and
// TLSV-045: every web case of the corpus ends in the code it expects, with the case's root standing in for
// the system store and its OCSP answer and CRL as the network.
func TestTLSV040TheWebCasesAreJudgedAsTheCorpusSays(t *testing.T) {
	m := readManifest(t)
	judged := 0
	for _, c := range m.Cases {
		trust := m.Trust[c.Trust]
		if trust.Profile != "web" {
			continue
		}
		judged++
		t.Run(c.Name, func(t *testing.T) {
			when, err := time.Parse(time.RFC3339, c.At)
			if err != nil {
				t.Fatal(err)
			}
			var roots []*x509.Certificate
			for _, root := range trust.Roots {
				roots = append(roots, corpusCert(t, root))
			}
			check := NewWebCheck(roots)
			var chain [][]byte
			for _, name := range c.Chain {
				chain = append(chain, corpusDER(t, name))
			}
			fetch := &network{ocsp: optionalFile(t, c.ResponderOCSP), crl: optionalFile(t, c.CRL)}
			verdict := check.Verify(t.Context(), chain, c.Host, optionalFile(t, c.StapledOCSP), when, fetch)
			if string(verdict.Code) != c.Expect {
				t.Errorf("code %s, expected %s: %s", verdict.Code, c.Expect, verdict.Detail)
			}
			if !slices.Equal(verdict.Warnings, c.Warnings) {
				t.Errorf("warnings %q, expected %q", verdict.Warnings, c.Warnings)
			}
			if verdict.Valid() != verdict.ReusableUntil.After(when) {
				t.Errorf("reusable until %s, valid %v", verdict.ReusableUntil, verdict.Valid())
			}
		})
	}
	if judged < 20 {
		t.Fatalf("only %d web cases", judged)
	}
}

// TLSV-030 to 033 through this package: every ti case of the corpus, judged by the ti verifier over a
// trust source as a handshake would judge it, ends in the code and warnings it expects.
func TestTLSV030TheTiCasesAreJudgedThroughTheVerifier(t *testing.T) {
	m := readManifest(t)
	judged := 0
	for _, c := range m.Cases {
		if m.Trust[c.Trust].Profile != "ti" {
			continue
		}
		judged++
		t.Run(c.Name, func(t *testing.T) {
			when, err := time.Parse(time.RFC3339, c.At)
			if err != nil {
				t.Fatal(err)
			}
			if c.CRL != nil {
				t.Fatalf("the ti profile has no CRL source, the case gives %s", *c.CRL)
			}
			clock := newClock(when)
			source := NewTrustSource(corpusStore(t, m, c.Trust))
			verifier := NewTiVerifier(source, responder(&network{ocsp: optionalFile(t, c.ResponderOCSP)}, clock), Options{Now: clock.Now})
			var chain [][]byte
			for _, name := range c.Chain {
				chain = append(chain, corpusDER(t, name))
			}
			verdict := verifier.Verify(t.Context(), chain, c.Host, optionalFile(t, c.StapledOCSP), when)
			if string(verdict.Code) != c.Expect {
				t.Errorf("code %s, expected %s: %s", verdict.Code, c.Expect, verdict.Detail)
			}
			if !slices.Equal(verdict.Warnings, c.Warnings) {
				t.Errorf("warnings %q, expected %q", verdict.Warnings, c.Warnings)
			}
			if verdict.Valid() != verdict.ReusableUntil.After(when) {
				t.Errorf("reusable until %s, valid %v", verdict.ReusableUntil, verdict.Valid())
			}
		})
	}
	if judged < 20 {
		t.Fatalf("only %d ti cases", judged)
	}
}
