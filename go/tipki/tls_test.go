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

package tipki

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"os"
	"slices"
	"testing"
	"time"
)

const tlsCorpusDir = "../../spec/pki-validation/testdata/"

type tlsManifest struct {
	Trust map[string]struct {
		Profile string   `json:"profile"`
		Roots   []string `json:"roots"`
		TSLCAs  *[]struct {
			Cert  string   `json:"cert"`
			Types []string `json:"types"`
		} `json:"tsl_cas"`
	} `json:"trust"`
	Cases []struct {
		Name          string   `json:"name"`
		Trust         string   `json:"trust"`
		Chain         []string `json:"chain"`
		Host          string   `json:"host"`
		At            string   `json:"at"`
		StapledOCSP   *string  `json:"stapled_ocsp"`
		ResponderOCSP *string  `json:"responder_ocsp"`
		CRL           *string  `json:"crl"`
		Expect        string   `json:"expect"`
		Warnings      []string `json:"warnings"`
		Rules         []string `json:"rules"`
	} `json:"cases"`
}

func tlsCorpusFile(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(tlsCorpusDir + name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func tlsCorpusCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	certs, err := ParsePEMCertificates(tlsCorpusFile(t, name))
	if err != nil || len(certs) != 1 {
		t.Fatalf("%s: %d certificates, %v", name, len(certs), err)
	}
	return certs[0]
}

// TLSV-020, TLSV-021, TLSV-022, TLSV-023, TLSV-024, TLSV-030, TLSV-031, TLSV-032 and TLSV-033: every ti case
// of the corpus ends in the code and warnings it expects. The TSL's CAs stand in for a verified list, as
// LoadTrustStore would set them, and the case's OCSP answer is played back as the responder's; a responder
// answers only when a case gives it an answer. The web cases are the TLS layer's.
func TestTLSV030TheTiCasesAreJudgedAsTheCorpusSays(t *testing.T) {
	var manifest tlsManifest
	if err := json.Unmarshal(tlsCorpusFile(t, "manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	judged := 0
	for _, c := range manifest.Cases {
		trust, ok := manifest.Trust[c.Trust]
		if !ok {
			t.Fatalf("%s: no trust material %q", c.Name, c.Trust)
		}
		if trust.Profile != "ti" {
			continue
		}
		judged++
		t.Run(c.Name, func(t *testing.T) {
			if c.CRL != nil {
				t.Fatalf("the ti profile has no CRL source, the case gives %s", *c.CRL)
			}
			at, err := time.Parse(time.RFC3339, c.At)
			if err != nil {
				t.Fatal(err)
			}
			var store *TrustStore
			if trust.TSLCAs != nil {
				store = &TrustStore{CATypes: map[string][]x509.OID{}}
				for _, root := range trust.Roots {
					store.Roots = append(store.Roots, tlsCorpusCert(t, root))
				}
				for _, ca := range *trust.TSLCAs {
					cert := tlsCorpusCert(t, ca.Cert)
					store.Intermediates = append(store.Intermediates, Intermediate{Certificate: cert, Provider: "TEST-ONLY"})
					for _, name := range ca.Types {
						certType, err := ParseCertificateType(name)
						if err != nil {
							t.Fatal(err)
						}
						store.CATypes[string(cert.Raw)] = append(store.CATypes[string(cert.Raw)], certType.OID())
					}
				}
			}
			var chain []*x509.Certificate
			for _, name := range c.Chain {
				chain = append(chain, tlsCorpusCert(t, name))
			}
			var stapled []byte
			if c.StapledOCSP != nil {
				stapled = tlsCorpusFile(t, *c.StapledOCSP)
			}
			transport := &fakeTransport{err: errors.New("no responder")}
			if c.ResponderOCSP != nil {
				transport = &fakeTransport{answers: [][]byte{tlsCorpusFile(t, *c.ResponderOCSP)}}
			}
			responder := checkerAt(transport, &at)
			responder.ResponderURL = ""

			verdict := NewServerCheck(store).Verify(t.Context(), chain, c.Host, stapled, at, responder)
			if string(verdict.Code) != c.Expect {
				t.Errorf("code %s, expected %s: %s", verdict.Code, c.Expect, verdict.Detail)
			}
			if !slices.Equal(verdict.Warnings, c.Warnings) {
				t.Errorf("warnings %q, expected %q", verdict.Warnings, c.Warnings)
			}
			if verdict.Valid() && (!verdict.NotAfter.Equal(chain[0].NotAfter) || verdict.ProducedAt.IsZero()) {
				t.Errorf("an accepted verdict without its reuse bounds: notAfter %s, producedAt %s", verdict.NotAfter, verdict.ProducedAt)
			}
		})
	}
	if judged < 20 {
		t.Fatalf("only %d ti cases", judged)
	}
}

// TLSV-032: the grace period is configurable (Tab_PKI_273); a stapled response older than it is no answer,
// and the responder is asked, with the warning.
func TestTLSV032AStapledResponseCountsWithinTheConfiguredGrace(t *testing.T) {
	store := &TrustStore{
		Roots:         []*x509.Certificate{tlsCorpusCert(t, "ti-root.pem")},
		Intermediates: []Intermediate{{Certificate: tlsCorpusCert(t, "ti-ca.pem"), Provider: "TEST-ONLY"}},
	}
	chain := []*x509.Certificate{tlsCorpusCert(t, "ti-good.pem"), tlsCorpusCert(t, "ti-ca.pem")}
	stale := tlsCorpusFile(t, "ocsp/ti-good-stale.der")
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	check := NewServerCheck(store)
	check.OCSPGrace = 2 * time.Hour
	verdict := check.Verify(t.Context(), chain, "svc.ti.test", stale, at, nil)
	if !verdict.Valid() || len(verdict.Warnings) != 0 {
		t.Fatalf("within a grace of two hours: %s %q: %s", verdict.Code, verdict.Warnings, verdict.Detail)
	}

	verdict = NewServerCheck(store).Verify(t.Context(), chain, "svc.ti.test", stale, at, nil)
	if verdict.Code != VerdictOCSPUnavailable || !slices.Equal(verdict.Warnings, []string{ProvidedOCSPResponseNotValid}) {
		t.Fatalf("past the default grace, no responder: %s %q: %s", verdict.Code, verdict.Warnings, verdict.Detail)
	}
}

// TLSV-033: without trust material no server is accepted, whatever it presents.
func TestTLSV033WithoutATrustStoreNoServerIsAccepted(t *testing.T) {
	verdict := NewServerCheck(nil).Verify(t.Context(), nil, "svc.ti.test", nil, time.Now(), nil)
	if verdict.Code != VerdictTrustMaterialUnavailable {
		t.Fatalf("got %s: %s", verdict.Code, verdict.Detail)
	}
}

// TLSV-024: case-insensitive, without a trailing dot; a wildcard is the whole leftmost label and stands for
// exactly one label.
func TestTLSV024NamesMatchExactlyOrByOneLeftmostWildcardLabel(t *testing.T) {
	for _, pair := range [][2]string{
		{"svc.ti.test", "svc.ti.test"},
		{"SVC.ti.test", "svc.TI.test"},
		{"svc.ti.test.", "svc.ti.test"},
		{"*.ti.test", "a.ti.test"},
		{"*.ti.test", "A.TI.TEST"},
	} {
		if !DNSNameMatches(pair[0], pair[1]) {
			t.Errorf("%s does not match %s", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{
		{"svc.ti.test", "other.ti.test"},
		{"*.ti.test", "ti.test"},
		{"*.ti.test", "a.b.ti.test"},
		{"*.ti.test", ".ti.test"},
		{"f*.ti.test", "foo.ti.test"},
		{"a.*.test", "a.b.test"},
		{"*.*.test", "a.b.test"},
		{"*.test", "a.test"},
		{"*", "test"},
		{"", ""},
		{"svc.ti.test", "svc.ti.test.evil"},
		{"bücher.test", "bücher.test"},
	} {
		if DNSNameMatches(pair[0], pair[1]) {
			t.Errorf("%s matches %s", pair[0], pair[1])
		}
	}
}

// TLSV-031: the commonName counts as a dNSName does, wildcards included, and the reference host loses one
// trailing dot. TLSV-024: an IP address matches only an iPAddress name of the same bytes, never a name.
func TestTLSV031TheCommonNameOrADNSNameNamesTheHost(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"alt.ti.test", "10.0.0.2"}, IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1).To4(), net.ParseIP("2001:db8::1")}}
	cert.Subject.CommonName = "*.ti.test"
	for host, want := range map[string]bool{
		"svc.ti.test":     true,
		"ALT.ti.test.":    true,
		"alt.ti.test..":   false,
		"a.b.ti.test":     false,
		"10.0.0.1":        true,
		"10.0.0.2":        false,
		"::ffff:10.0.0.1": false,
		"2001:db8::1":     true,
		"2001:db8::1%en0": false,
		"":                false,
	} {
		if got := NamesHost(cert, host); got != want {
			t.Errorf("%q: %v, expected %v", host, got, want)
		}
	}
	cnOnly := &x509.Certificate{}
	cnOnly.Subject.CommonName = "svc.ti.test"
	if !NamesHost(cnOnly, "svc.ti.test") || NamesHost(cnOnly, "other.ti.test") {
		t.Error("the commonName alone does not decide")
	}
}
