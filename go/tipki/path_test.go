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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const pathCorpusDir = "../../spec/pki-path/testdata/"

type pathCase struct {
	Name       string     `json:"name"`
	Now        int64      `json:"now"`
	Compromise bool       `json:"compromise"`
	Chain      []string   `json:"chain"`
	Incomplete bool       `json:"incomplete"`
	Errors     [][]string `json:"errors"`
	Warnings   [][]string `json:"warnings"`
}

func pathFixtures(t *testing.T) map[string]*x509.Certificate {
	t.Helper()
	files, err := filepath.Glob("../../rust/ti-pki/tests/pki/*.pem")
	if err != nil {
		t.Fatal(err)
	}
	certs := make(map[string]*x509.Certificate)
	for _, file := range files {
		name := filepath.Base(file)
		if strings.HasPrefix(name, "ocsp-") {
			continue
		}
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(body)
		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		certs[name] = cert
	}
	return certs
}

func tamperedCopy(t *testing.T, cert *x509.Certificate) *x509.Certificate {
	t.Helper()
	der := bytes.Clone(cert.Raw)
	der[len(der)-1] ^= 1
	parsed, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func codes(findings []Finding) []string {
	out := []string{}
	for _, finding := range findings {
		out = append(out, finding.Code+"|"+finding.Subject)
	}
	return out
}

func wanted(pairs [][]string) []string {
	out := []string{}
	for _, pair := range pairs {
		out = append(out, pair[0]+"|"+pair[1])
	}
	return out
}

// PATH-001 to PATH-006: every fixture, at three times and under both models, and tampered.
func TestPATH001EveryPathIsJudgedAsInTiPki(t *testing.T) {
	var cases []pathCase
	readJSON(t, pathCorpusDir+"path.json", &cases)
	if len(cases) < 150 {
		t.Fatalf("%d cases", len(cases))
	}
	certs := pathFixtures(t)
	var names []string
	for name := range certs {
		names = append(names, name)
	}
	slices.Sort(names)
	isRoot := func(name string) bool { return name == "rca-rsa.pem" || name == "rca1.pem" || name == "rca7.pem" }
	var roots []*x509.Certificate
	for _, name := range names {
		if isRoot(name) {
			roots = append(roots, certs[name])
		}
	}
	nameOf := func(cert *x509.Certificate) string {
		for name, candidate := range certs {
			if candidate.Equal(cert) {
				return name
			}
		}
		return "tampered"
	}
	for _, want := range cases {
		label := fmt.Sprintf("%s@%d/%v", want.Name, want.Now, want.Compromise)
		t.Run(label, func(t *testing.T) {
			fixture := strings.TrimPrefix(want.Name, "tampered:")
			var intermediates []*x509.Certificate
			for _, name := range names {
				if name != fixture && !isRoot(name) {
					intermediates = append(intermediates, certs[name])
				}
			}
			leaf := certs[fixture]
			if fixture != want.Name {
				leaf = tamperedCopy(t, leaf)
			}
			chain, err := BuildChain(leaf, intermediates, roots)
			if (err != nil) != want.Incomplete {
				t.Fatalf("%v, ti-pki incomplete=%v", err, want.Incomplete)
			}
			got := []string{}
			for _, cert := range chain {
				got = append(got, nameOf(cert))
			}
			if !slices.Equal(got, want.Chain) {
				t.Fatalf("chain %v, ti-pki has %v", got, want.Chain)
			}
			if want.Incomplete {
				return
			}
			model := ValidityShell
			if want.Compromise {
				model = ValidityCompromise
			}
			result, err := ValidatePath(chain, PathOptions{Now: time.Unix(want.Now, 0), Model: model})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(codes(result.Errors), wanted(want.Errors)) {
				t.Errorf("errors %v, ti-pki has %v", codes(result.Errors), wanted(want.Errors))
			}
			if !slices.Equal(codes(result.Warnings), wanted(want.Warnings)) {
				t.Errorf("warnings %v, ti-pki has %v", codes(result.Warnings), wanted(want.Warnings))
			}
		})
	}
}

// No fixture is a CA without keyCertSign, so the corpus cannot show this rule. These certificates are
// made here, and the same chain with the bit set shows that it alone decides.
func TestPATH005ACAMustAllowCertificateSigning(t *testing.T) {
	for _, test := range []struct {
		name  string
		usage x509.KeyUsage
		want  []string
	}{
		{"without keyCertSign", x509.KeyUsageDigitalSignature, []string{"key_usage_mismatch|ca"}},
		{"with keyCertSign", x509.KeyUsageCertSign, []string{}},
		{"no key usage extension", 0, []string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			issue := func(subject, issuer string, serial int64, usage x509.KeyUsage, isCA bool, parent *x509.Certificate) *x509.Certificate {
				template := &x509.Certificate{
					SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: subject}, Issuer: pkix.Name{CommonName: issuer},
					NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: usage,
					BasicConstraintsValid: true, IsCA: isCA,
				}
				if parent == nil {
					parent = template
				}
				der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), key)
				if err != nil {
					t.Fatal(err)
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				return cert
			}
			root := issue("root", "root", 1, x509.KeyUsageCertSign, true, nil)
			ca := issue("ca", "root", 2, test.usage, true, root)
			leaf := issue("leaf", "ca", 3, x509.KeyUsageDigitalSignature, false, ca)
			result, err := ValidatePath([]*x509.Certificate{leaf, ca, root}, PathOptions{Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if got := codes(result.Errors); !slices.Equal(got, test.want) {
				t.Errorf("%v, want %v", got, test.want)
			}
		})
	}
}

// No fixture pairs a curve with the other hash, so these are made here. ti-pki's algorithm set has one
// hash per curve, and its own test of this is in algorithms/mod.rs.
func TestPATH006ACurveTakesOneHash(t *testing.T) {
	for _, test := range []struct {
		name      string
		curve     elliptic.Curve
		algorithm x509.SignatureAlgorithm
		admitted  bool
	}{
		{"P-256 with SHA-256", elliptic.P256(), x509.ECDSAWithSHA256, true},
		{"P-256 with SHA-384", elliptic.P256(), x509.ECDSAWithSHA384, false},
		{"P-384 with SHA-384", elliptic.P384(), x509.ECDSAWithSHA384, true},
		{"P-384 with SHA-256", elliptic.P384(), x509.ECDSAWithSHA256, false},
		{"P-521 with SHA-512", elliptic.P521(), x509.ECDSAWithSHA512, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(test.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, SignatureAlgorithm: test.algorithm,
				NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifySignedBy(cert, cert); (err == nil) != test.admitted {
				t.Errorf("%v, admitted %v", err, test.admitted)
			}
		})
	}
}

func TestPATH005AChainNeedsAnEndEntityAndARoot(t *testing.T) {
	certs := pathFixtures(t)
	if _, err := ValidatePath([]*x509.Certificate{certs["rca1.pem"]}, PathOptions{Now: time.Now()}); err == nil {
		t.Error("a chain of one")
	}
}

// BUNDLE-001: read or refused as in ti-pki.
func TestBUNDLE001ValuesAreReadOrRefusedAsStated(t *testing.T) {
	var vectors []struct {
		Name      string  `json:"name"`
		JSON      string  `json:"json"`
		Accept    bool    `json:"accept"`
		Roots     string  `json:"roots"`
		TSL       string  `json:"tsl"`
		Signature string  `json:"signature"`
		Status    *string `json:"status"`
		FetchedAt int64   `json:"fetched_at"`
		Anchor    string  `json:"anchor"`
	}
	readJSON(t, pathCorpusDir+"bundle.json", &vectors)
	if len(vectors) < 40 {
		t.Fatalf("%d vectors", len(vectors))
	}
	b64 := base64.StdEncoding.EncodeToString
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			got, err := ParseBundle([]byte(vector.JSON))
			if (err == nil) != vector.Accept {
				t.Fatalf("%+v %v", got, err)
			}
			if err != nil {
				return
			}
			if b64(got.Roots) != vector.Roots || b64(got.TSL) != vector.TSL || b64(got.TSLSignature) != vector.Signature {
				t.Errorf("%+v", got)
			}
			if got.FetchedAt.Unix() != vector.FetchedAt {
				t.Errorf("fetched at %d", got.FetchedAt.Unix())
			}
			if (got.TSLSignerStatus != nil) != (vector.Status != nil) || (vector.Status != nil && b64(got.TSLSignerStatus) != *vector.Status) {
				t.Errorf("status %v", got.TSLSignerStatus)
			}
			if hex.EncodeToString(got.AnchorSHA256[:]) != strings.ToLower(vector.Anchor) {
				t.Errorf("anchor %x", got.AnchorSHA256)
			}
		})
	}
}

func TestBUNDLE002AnotherEnvironmentsBundleIsRefused(t *testing.T) {
	bundle := &Bundle{Label: "x"}
	if err := bundle.CheckAnchor([]byte("anchor")); err == nil {
		t.Error("an anchor that is not the bundle's")
	}
}

func FuzzParseBundle(f *testing.F) {
	f.Add([]byte(`{"format_version":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		bundle, err := ParseBundle(data)
		if (bundle == nil) != (err != nil) {
			t.Errorf("%+v %v", bundle, err)
		}
		if bundle != nil && bundle.TSLSignature == nil {
			t.Error("a bundle without a signature")
		}
	})
}
