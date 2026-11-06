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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const crlURL = "http://crl.web.test/ca.crl"

type idpName struct {
	FullName []asn1.RawValue `asn1:"optional,tag:0"`
}

type idp struct {
	DistributionPoint idpName `asn1:"optional,tag:0"`
	OnlyUser          bool    `asn1:"optional,tag:1"`
	OnlyCA            bool    `asn1:"optional,tag:2"`
	Indirect          bool    `asn1:"optional,tag:4"`
}

func idpExtension(t *testing.T, point idp) pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal(point)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidIssuingDistributionPoint, Critical: true, Value: value}
}

func uri(text string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(text)}
}

// TLSV-044: a CRL counts when the issuer signed it, the reference time lies in its window, and it covers the
// end entity's distribution point; otherwise it gives no status, and nothing is refused or accepted on it.
func TestTLSV044ACRLCountsOnlyWhenItHoldsForTheCertificate(t *testing.T) {
	root := issue(t, caTemplate("CRL Root TEST-ONLY", at.Add(-time.Hour)), nil)
	ca := issue(t, caTemplate("CRL CA TEST-ONLY", at.Add(-time.Hour)), root)
	template := serverTemplate("www.web.test", at.Add(-time.Hour))
	template.CRLDistributionPoints = []string{crlURL}
	leaf := issue(t, template, ca)

	crl := func(signer *issued, thisUpdate, nextUpdate time.Time, revoked bool, extensions ...pkix.Extension) []byte {
		list := &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: nextUpdate, ExtraExtensions: extensions,
		}
		if revoked {
			list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: leaf.cert.SerialNumber, RevocationTime: thisUpdate}}
		}
		der, err := x509.CreateRevocationList(rand.Reader, list, signer.cert, signer.key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	day := 24 * time.Hour
	for name, tc := range map[string]struct {
		der          []byte
		counts, gone bool
	}{
		"good":                       {crl(ca, at, at.Add(day), false), true, false},
		"revoked":                    {crl(ca, at, at.Add(day), true), true, true},
		"its distribution point":     {crl(ca, at, at.Add(day), true, idpExtension(t, idp{DistributionPoint: idpName{FullName: []asn1.RawValue{uri(crlURL)}}, OnlyUser: true})), true, true},
		"another distribution point": {crl(ca, at, at.Add(day), true, idpExtension(t, idp{DistributionPoint: idpName{FullName: []asn1.RawValue{uri("http://crl.web.test/other.crl")}}})), false, false},
		"CA certificates only":       {crl(ca, at, at.Add(day), true, idpExtension(t, idp{OnlyCA: true})), false, false},
		"indirect":                   {crl(ca, at, at.Add(day), true, idpExtension(t, idp{Indirect: true})), false, false},
		"an unknown critical extension": {crl(ca, at, at.Add(day), true, pkix.Extension{
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0},
		}), false, false},
		"a delta CRL":         {crl(ca, at, at.Add(day), true, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{2, 1, 1}}), false, false},
		"past its nextUpdate": {crl(ca, at.Add(-2*day), at, true), false, false},
		"not yet issued":      {crl(ca, at.Add(time.Minute), at.Add(day), true), false, false},
		"signed by the root":  {crl(root, at, at.Add(day), true), false, false},
		"no CRL at all":       {[]byte("not a CRL"), false, false},
	} {
		revoked, nextUpdate, counts := crlStatus(tc.der, crlURL, leaf.cert, ca.cert, at)
		if counts != tc.counts || revoked != tc.gone {
			t.Errorf("%s: counts %v revoked %v, expected %v %v", name, counts, revoked, tc.counts, tc.gone)
		}
		if counts && !nextUpdate.Equal(at.Add(day)) {
			t.Errorf("%s: nextUpdate %s", name, nextUpdate)
		}
	}

	// The CRL's nextUpdate bounds the reuse of the verdict it gave (TLSV-050).
	verdict := revocation(t.Context(), leaf.cert, ca.cert, nil, at, &network{crl: crl(ca, at, at.Add(time.Hour), false)})
	if !verdict.Valid() || !verdict.ReusableUntil.Equal(at.Add(time.Hour)) {
		t.Fatalf("%s until %s", verdict.Code, verdict.ReusableUntil)
	}
}

// TLSV-044: the host's HTTP reaches responders and CRL hosts with the OCSP media types, follows only http
// and https, and gives up on an answer larger than its limit or other than 200.
func TestTLSV044TheHTTPFetcherBoundsWhatItReads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocsp":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/ocsp-request" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("answer"))
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 100)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	fetch := &HTTPFetcher{Client: server.Client(), MaxCRLBytes: 99}

	if body, err := fetch.OCSP(t.Context(), server.URL+"/ocsp", []byte("request")); err != nil || string(body) != "answer" {
		t.Fatalf("OCSP: %q, %v", body, err)
	}
	for name, err := range map[string]error{
		"over the limit": func() error { _, err := fetch.CRL(t.Context(), server.URL+"/big"); return err }(),
		"not found":      func() error { _, err := fetch.CRL(t.Context(), server.URL+"/none"); return err }(),
		"ldap":           func() error { _, err := fetch.CRL(t.Context(), "ldap://crl.web.test/cn=CA"); return err }(),
		"no client": func() error {
			_, err := (&HTTPFetcher{}).CRL(t.Context(), server.URL+"/big")
			return err
		}(),
	} {
		if err == nil {
			t.Errorf("%s: answered", name)
		}
	}
	if body, err := (&HTTPFetcher{Client: server.Client(), MaxCRLBytes: 100}).CRL(t.Context(), server.URL+"/big"); err != nil || len(body) != 100 {
		t.Fatalf("at the limit: %d bytes, %v", len(body), err)
	}
}
