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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/gematik/zero-lab/go/tipki/oid"
)

const (
	corpusDir   = "../../spec/pki-profiles/testdata/"
	fixturesDir = "../../rust/ti-pki/tests/pki/types/"
)

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatal(err)
	}
}

type corpusFile struct {
	Tables struct {
		Types []struct {
			Name        string   `json:"name"`
			OID         string   `json:"oid"`
			KeyUsage    []string `json:"key_usage"`
			ExtKeyUsage []string `json:"ext_key_usage"`
			Policies    []string `json:"policies"`
			RoleOIDs    []string `json:"role_oids"`
		} `json:"types"`
		Profiles []struct {
			Name             string   `json:"name"`
			Description      string   `json:"description"`
			Revocation       string   `json:"revocation"`
			RequiredRoleOIDs []string `json:"required_role_oids"`
			AcceptsTypes     []string `json:"accepts_types"`
			DefaultFor       []string `json:"default_for"`
		} `json:"profiles"`
		OIDs []struct {
			OID              string   `json:"oid"`
			Reference        string   `json:"reference"`
			Description      string   `json:"description"`
			Document         string   `json:"document"`
			CertificateTypes []string `json:"certificate_types"`
		} `json:"oids"`
		Professions  []string `json:"professions"`
		Institutions []string `json:"institutions"`
		ErrorCodes   []string `json:"error_codes"`
	} `json:"tables"`
	Certificates []struct {
		File      string `json:"file"`
		Type      string `json:"type"`
		Admission *struct {
			Items              []string `json:"items"`
			OIDs               []string `json:"oids"`
			RegistrationNumber string   `json:"registration_number"`
		} `json:"admission"`
		Selection struct {
			Profile    string   `json:"profile"`
			Reason     string   `json:"reason"`
			Candidates []string `json:"candidates"`
		} `json:"selection"`
		Findings map[string][]string `json:"findings"`
	} `json:"certificates"`
}

func keyUsageBits(names []string) x509.KeyUsage {
	bits := map[string]x509.KeyUsage{
		"digitalSignature":  x509.KeyUsageDigitalSignature,
		"contentCommitment": x509.KeyUsageContentCommitment,
		"keyAgreement":      x509.KeyUsageKeyAgreement,
	}
	var usage x509.KeyUsage
	for _, name := range names {
		usage |= bits[name]
	}
	return usage
}

// oidTexts gives ids in the dotted form the corpus states them in.
func oidTexts(ids []x509.OID) []string {
	texts := make([]string, len(ids))
	for i, id := range ids {
		texts[i] = id.String()
	}
	return texts
}

func equalStrings(a, b []string) bool { return slices.Equal(a, b) || (len(a) == 0 && len(b) == 0) }

// PROF-030: the tables of certificate types and profiles are ti-pki's, entry for entry.
func TestPROF030TheTablesAreThoseOfTiPki(t *testing.T) {
	var corpus corpusFile
	readJSON(t, corpusDir+"corpus.json", &corpus)
	types := AllCertificateTypes()
	if len(types) != len(corpus.Tables.Types) {
		t.Fatalf("%d types, ti-pki has %d", len(types), len(corpus.Tables.Types))
	}
	for i, want := range corpus.Tables.Types {
		got := types[i]
		spec := got.Spec()
		if string(got) != want.Name || got.OID().String() != want.OID || spec.KeyUsage != keyUsageBits(want.KeyUsage) ||
			!equalStrings(oidTexts(spec.ExtKeyUsage), want.ExtKeyUsage) || !equalStrings(oidTexts(spec.Policies), want.Policies) ||
			!equalStrings(oidTexts(spec.RoleOIDs), want.RoleOIDs) {
			t.Errorf("%s: %+v, ti-pki has %+v", got, spec, want)
		}
	}
	profiles := Profiles()
	if len(profiles) != len(corpus.Tables.Profiles) {
		t.Fatalf("%d profiles, ti-pki has %d", len(profiles), len(corpus.Tables.Profiles))
	}
	names := func(types []CertificateType) []string {
		out := make([]string, len(types))
		for i, one := range types {
			out[i] = string(one)
		}
		return out
	}
	for i, want := range corpus.Tables.Profiles {
		got := profiles[i]
		if got.Name != want.Name || got.Description != want.Description || string(got.Revocation) != want.Revocation ||
			!equalStrings(oidTexts(got.RequiredRoleOIDs), want.RequiredRoleOIDs) ||
			!equalStrings(names(got.AcceptsTypes), want.AcceptsTypes) || !equalStrings(names(got.DefaultFor), want.DefaultFor) {
			t.Errorf("%s: %+v, ti-pki has %+v", got.Name, got, want)
		}
	}
}

func certificateFile(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	body, err := os.ReadFile(fixturesDir + name)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(body)
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// PROF-031: package oid is ti-pki's table, entry for entry and in its order.
func TestPROF031TheIdentifiersAreThoseOfTiPki(t *testing.T) {
	var corpus corpusFile
	readJSON(t, corpusDir+"corpus.json", &corpus)
	all := oid.All()
	if len(all) != len(corpus.Tables.OIDs) {
		t.Fatalf("%d identifiers, ti-pki has %d", len(all), len(corpus.Tables.OIDs))
	}
	for i, want := range corpus.Tables.OIDs {
		got := all[i]
		if got.OID.String() != want.OID || got.Reference != want.Reference || got.Description != want.Description ||
			got.Document != want.Document || !equalStrings(got.CertificateTypes, want.CertificateTypes) {
			t.Errorf("%+v, ti-pki has %+v", got, want)
		}
	}
	if !equalStrings(oidTexts(oid.Professions), corpus.Tables.Professions) || !equalStrings(oidTexts(oid.Institutions), corpus.Tables.Institutions) {
		t.Error("the tables of professions and institutions differ")
	}
	if got := oid.Format(oid.TechRoleZETAGuard); got != "1.2.276.0.76.4.328 (ZETA Guard)" {
		t.Errorf("%q", got)
	}
	if got := oid.Format(oid.MustParse("1.2.3")); got != "1.2.3" {
		t.Errorf("%q", got)
	}
}

// PROF-001, 002, 003, 010, 020: every fixture reads as it does in ti-pki.
func TestPROF030EveryCertificateReadsAsInTiPki(t *testing.T) {
	var corpus corpusFile
	readJSON(t, corpusDir+"corpus.json", &corpus)
	if len(corpus.Certificates) < 40 {
		t.Fatalf("%d certificates", len(corpus.Certificates))
	}
	for _, want := range corpus.Certificates {
		t.Run(want.File, func(t *testing.T) {
			cert := certificateFile(t, want.File)
			got, ok := DetectCertificateType(cert)
			if string(got) != want.Type || ok != (want.Type != "") {
				t.Errorf("type %q, ti-pki has %q", got, want.Type)
			}

			admission, err := Admission(cert)
			switch {
			case want.Admission == nil:
				if !errors.Is(err, ErrNoAdmissionStatement) {
					t.Errorf("admission %+v %v, ti-pki has none", admission, err)
				}
			case err != nil:
				t.Errorf("admission: %v", err)
			case !equalStrings(admission.ProfessionItems, want.Admission.Items) ||
				!equalStrings(oidTexts(admission.ProfessionOIDs), want.Admission.OIDs) ||
				admission.RegistrationNumber != want.Admission.RegistrationNumber:
				t.Errorf("admission %+v, ti-pki has %+v", admission, want.Admission)
			}

			selection := SelectForCert(cert)
			name := ""
			if selection.Profile != nil {
				name = selection.Profile.Name
			}
			candidates := []string{}
			for _, p := range selection.Candidates {
				candidates = append(candidates, p.Name)
			}
			if name != want.Selection.Profile || string(selection.Reason) != want.Selection.Reason ||
				!equalStrings(candidates, want.Selection.Candidates) {
				t.Errorf("selection %q %q %v, ti-pki has %+v", name, selection.Reason, candidates, want.Selection)
			}

			if !ok {
				return
			}
			for _, profile := range Profiles() {
				codes := []string{}
				for _, finding := range profile.Check(cert, got) {
					codes = append(codes, string(finding.Code))
				}
				if !reflect.DeepEqual(codes, append([]string{}, want.Findings[profile.Name]...)) {
					t.Errorf("%s: %v, ti-pki has %v", profile.Name, codes, want.Findings[profile.Name])
				}
			}
		})
	}
}

// PROF-010, 011: read or refused as in ti-pki, the malformed values above all.
func TestPROF010AdmissionValuesAreReadOrRefusedAsStated(t *testing.T) {
	var vectors []struct {
		Name               string   `json:"name"`
		DER                string   `json:"der"`
		Accept             bool     `json:"accept"`
		Items              []string `json:"items"`
		OIDs               []string `json:"oids"`
		RegistrationNumber string   `json:"registration_number"`
	}
	readJSON(t, corpusDir+"admission.json", &vectors)
	if len(vectors) < 25 {
		t.Fatalf("%d vectors", len(vectors))
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			der, err := hex.DecodeString(vector.DER)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseAdmission(der)
			if (err == nil) != vector.Accept {
				t.Fatalf("%+v %v", got, err)
			}
			if err == nil && (!equalStrings(got.ProfessionItems, vector.Items) ||
				!equalStrings(oidTexts(got.ProfessionOIDs), vector.OIDs) || got.RegistrationNumber != vector.RegistrationNumber) {
				t.Errorf("%+v", got)
			}
		})
	}
}

func TestPROF001NamesFoldLikeThoseOfTiPki(t *testing.T) {
	for _, name := range []string{"C.HCI.AUT", "HCI.AUT", "hci-aut", " c.hci.aut "} {
		if got, err := ParseCertificateType(name); err != nil || got != CertHciAut {
			t.Errorf("%q: %q %v", name, got, err)
		}
	}
	if _, err := ParseCertificateType("C.NOPE"); err == nil {
		t.Error("an unknown type")
	}
	if LookupProfile("C.HCI.AUT") != ProfileHciAut || LookupProfile("none") != nil {
		t.Error("profile lookup")
	}
}

// Whatever a certificate's extension holds, the parser answers and every first element is real.
func FuzzParseAdmission(f *testing.F) {
	var vectors []struct {
		DER string `json:"der"`
	}
	if body, err := os.ReadFile(corpusDir + "admission.json"); err == nil && json.Unmarshal(body, &vectors) == nil {
		for _, vector := range vectors {
			if der, err := hex.DecodeString(vector.DER); err == nil {
				f.Add(der)
			}
		}
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		statement, err := ParseAdmission(der)
		if (statement == nil) != (err != nil) {
			t.Errorf("%+v %v", statement, err)
		}
	})
}

// An unknown type's OID is empty, and x509.OID's Equal holds for two empty values: neither may count as a match.
func TestAnEmptyOIDMatchesNothing(t *testing.T) {
	var empty x509.OID
	if _, ok := typeByOID(empty); ok {
		t.Error("an empty OID has a certificate type")
	}
	if _, ok := oid.Lookup(empty); ok {
		t.Error("an empty OID has a table entry")
	}
	if got := oid.Format(empty); got != "" {
		t.Errorf("Format: %q", got)
	}
	if containsOID([]x509.OID{empty}, empty) {
		t.Error("an empty OID is listed by a list holding one")
	}

	leaf, issuer := pkiCert(t, "types/type-hci-aut.pem"), pkiCert(t, "sub-ca-komp.pem")
	validator := NewValidator(&TrustStore{CATypes: map[string][]x509.OID{string(issuer.Raw): {empty}}})
	var result ValidationResult
	validator.checkTSLType([]*x509.Certificate{leaf, issuer}, CertificateType("no such type"), &result)
	if len(result.Errors) != 1 || result.Errors[0].Code != "cert_type_ca_not_authorized" {
		t.Errorf("an unknown type passed on an empty entry: %+v", result.Errors)
	}
}
