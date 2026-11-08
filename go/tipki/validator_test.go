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
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const validateNow = 1767225600

// scripted answers with one outcome and records whom it was asked about. The ca_* scripts answer good for the end
// entity and fail for a CA, which no validator may ask about (VALID-008).
type scripted struct {
	script string
	asked  []string
}

func newScripted(script string) *scripted { return &scripted{script: script} }

func (s *scripted) Check(_ context.Context, cert, _ *x509.Certificate, _ *TrustStore) (*RevocationResult, error) {
	s.asked = append(s.asked, cert.Subject.CommonName)
	result := &RevocationResult{Status: RevocationUnknown, CheckedAt: time.Unix(validateNow, 0), Reason: "scripted", ResponderName: "scripted responder"}
	script := s.script
	switch {
	case (script == "ca_untrusted" || script == "ca_unavailable") && !cert.IsCA:
		script = "good"
	case script == "ca_untrusted":
		script = "untrusted"
	case script == "ca_unavailable":
		script = "unavailable"
	}
	switch script {
	case "good":
		result.Status = RevocationGood
	case "tsl_listed":
		result.Status = RevocationGood
		result.Authorization = &ResponderAuthorization{Kind: "tsl_listed", TSP: "some TSP"}
	case "revoked":
		result.Status, result.RevokedAt = RevocationRevoked, time.Unix(validateNow-3600, 0)
	case "revoked_later":
		result.Status, result.RevokedAt = RevocationRevoked, time.Unix(validateNow+3600, 0)
	case "revoked_no_time":
		result.Status = RevocationRevoked
	case "unknown":
	case "unavailable":
		return nil, &OCSPError{Code: "ocsp_unavailable", Subject: cert.Subject.CommonName, Message: "scripted"}
	case "invalid":
		return nil, &OCSPError{Code: "ocsp_response_invalid", Subject: cert.Subject.CommonName, Message: "scripted"}
	case "untrusted":
		return nil, &OCSPError{Code: "ocsp_responder_untrusted", Subject: cert.Subject.CommonName, Message: "scripted"}
	default:
		return nil, errors.New("no such script")
	}
	return result, nil
}

type verdictJSON struct {
	Valid      bool       `json:"valid"`
	Chain      []string   `json:"chain"`
	Positions  []string   `json:"positions"`
	Revocation []*string  `json:"revocation"`
	Errors     [][]string `json:"errors"`
	Warnings   [][]string `json:"warnings"`
	Asked      []string   `json:"asked"`
}

type validateCorpus struct {
	Matrix []struct {
		File           string      `json:"file"`
		Kind           string      `json:"kind"`
		Profile        string      `json:"profile"`
		Type           string      `json:"type"`
		Now            int64       `json:"now"`
		Mode           string      `json:"mode"`
		Script         string      `json:"script"`
		CARevokedSince *int64      `json:"ca_revoked_since"`
		FQDN           string      `json:"fqdn"`
		AllowExpired   bool        `json:"allow_expired"`
		Verdict        verdictJSON `json:"verdict"`
	} `json:"matrix"`
	Compromise []struct {
		File    string      `json:"file"`
		Now     int64       `json:"now"`
		Script  string      `json:"script"`
		Verdict verdictJSON `json:"verdict"`
	} `json:"compromise"`
	Real []struct {
		Profile string      `json:"profile"`
		Verdict verdictJSON `json:"verdict"`
	} `json:"real"`
	Signer verdictJSON `json:"signer"`
	// The types the real list states per CA, and those its statement lets a real SMC-B's CA issue.
	CATypes    [][]any     `json:"ca_types"`
	Authorized []string    `json:"authorized"`
	Unlisted   verdictJSON `json:"unlisted"`
}

func describeVerdict(valid bool, chain, positions, revocation, errs, warnings []string) string {
	return fmt.Sprintf("valid=%v chain=%v positions=%v revocation=%v errors=%v warnings=%v", valid, chain, positions, revocation, errs, warnings)
}

func describeWantedVerdict(want verdictJSON) string {
	var revocation []string
	for _, status := range want.Revocation {
		if status == nil {
			revocation = append(revocation, "-")
		} else {
			revocation = append(revocation, *status)
		}
	}
	return describeVerdict(want.Valid, want.Chain, want.Positions, revocation, wanted(want.Errors), wanted(want.Warnings))
}

func describeResult(result *ValidationResult) string {
	var chain, positions, revocation []string
	for _, cert := range result.Chain {
		chain = append(chain, cert.Subject.CommonName)
	}
	for _, r := range result.CertResults {
		positions = append(positions, string(r.Position))
		if r.Revocation == nil {
			revocation = append(revocation, "-")
		} else {
			revocation = append(revocation, string(r.Revocation.Status))
		}
	}
	return describeVerdict(result.Valid, chain, positions, revocation, codes(result.Errors), codes(result.Warnings))
}

func validateFixtures(t *testing.T) (map[string]*x509.Certificate, []string) {
	t.Helper()
	certs := make(map[string]*x509.Certificate)
	var names []string
	for _, pattern := range []string{"../../rust/ti-pki/tests/pki/*.pem", "../../rust/ti-pki/tests/pki/types/*.pem"} {
		files, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			name := filepath.Base(file)
			if strings.HasPrefix(name, "ocsp-") {
				continue
			}
			if strings.Contains(file, "/types/") {
				name = "types/" + name
			}
			certs[name] = certificateAt(t, file)
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return certs, names
}

func isRootFixture(name string) bool {
	return name == "rca1.pem" || name == "rca7.pem" || name == "rca-rsa.pem"
}

// VALID-001 to 003: every fixture under every profile, every revocation outcome in every mode, a CA the list
// revoked, the expected name and allowed expiry.
func TestVALID001EveryVerdictIsThatOfTiPki(t *testing.T) {
	var corpus validateCorpus
	readJSON(t, pathCorpusDir+"validate.json", &corpus)
	if len(corpus.Matrix) < 2000 {
		t.Fatalf("%d cases", len(corpus.Matrix))
	}
	certs, names := validateFixtures(t)
	store := func(since *int64) *TrustStore {
		built := &TrustStore{}
		for _, name := range names {
			cert := certs[name]
			switch {
			case isRootFixture(name):
				built.Roots = append(built.Roots, cert)
			case cert.BasicConstraintsValid && cert.IsCA && !strings.HasPrefix(name, "rogue"):
				intermediate := Intermediate{Certificate: cert, Provider: "TSP"}
				if since != nil {
					intermediate.RevokedSince = time.Unix(*since, 0)
				}
				built.Intermediates = append(built.Intermediates, intermediate)
			}
		}
		return built
	}
	plain := store(nil)
	failures := 0
	for _, want := range corpus.Matrix {
		leaf := certs[want.File]
		input := []*x509.Certificate{leaf}
		for _, name := range names {
			if !isRootFixture(name) && name != want.File {
				input = append(input, certs[name])
			}
		}
		chosen := plain
		if want.CARevokedSince != nil {
			chosen = store(want.CARevokedSince)
		}
		mode := RevocationMode(want.Mode)
		var validator *Validator
		if want.Kind == "profile" {
			validator = LookupProfile(want.Profile).Validator(chosen, CertificateType(want.Type), mode)
		} else {
			validator = NewValidator(chosen)
			validator.Revocation = mode
		}
		validator.ExpectedFQDN, validator.AllowExpired = want.FQDN, want.AllowExpired
		checker := newScripted(want.Script)
		result, err := validator.Validate(context.Background(), input, time.Unix(want.Now, 0), checker)
		if err != nil {
			t.Fatal(err)
		}
		got := describeResult(result) + fmt.Sprintf(" asked=%v", checker.asked)
		if expected := describeWantedVerdict(want.Verdict) + fmt.Sprintf(" asked=%v", want.Verdict.Asked); got != expected {
			if failures++; failures <= 10 {
				t.Errorf("%s kind=%s profile=%s @%d mode=%s script=%s since=%v fqdn=%q expired=%v:\n got  %s\n want %s", want.File, want.Kind, want.Profile, want.Now-validateNow, want.Mode, want.Script, want.CARevokedSince, want.FQDN, want.AllowExpired, got, expected)
			}
		}
	}
	if failures > 0 {
		t.Errorf("%d of %d differ", failures, len(corpus.Matrix))
	}
}

// VALID-008 with the Kompromissmodell: GEM.SubCA-Short, expired, stays in accord in a list that lets it issue SMC-B
// and HBA certificates. Its SMC-B's and HBA's certificates validate with ca_expired, and a responder that
// refuses every CA is never asked about it; a component's certificate under it is expired (shell model).
func TestVALID008ACAExpiredUnderTheKompromissmodellIsNotAsked(t *testing.T) {
	var corpus validateCorpus
	readJSON(t, pathCorpusDir+"validate.json", &corpus)
	if len(corpus.Compromise) != 3 {
		t.Fatalf("%d cases", len(corpus.Compromise))
	}
	ca := pkiCert(t, "sub-ca-short.pem")
	store := &TrustStore{
		Roots:         []*x509.Certificate{pkiCert(t, "rca1.pem")},
		Intermediates: []Intermediate{{Certificate: ca, Provider: "TSP"}},
		CATypes:       map[string][]x509.OID{string(ca.Raw): {CertHciAut.OID(), CertHpAut.OID(), CertFdTLSS.OID()}},
	}
	for _, want := range corpus.Compromise {
		checker := newScripted(want.Script)
		result, err := NewValidator(store).Validate(context.Background(), []*x509.Certificate{pkiCert(t, want.File)}, time.Unix(want.Now, 0), checker)
		if err != nil {
			t.Fatal(err)
		}
		got := describeResult(result) + fmt.Sprintf(" asked=%v", checker.asked)
		if expected := describeWantedVerdict(want.Verdict) + fmt.Sprintf(" asked=%v", want.Verdict.Asked); got != expected {
			t.Errorf("%s:\n got  %s\n want %s", want.File, got, expected)
		}
	}
}

func refBundle(t *testing.T, now time.Time) *TrustStore {
	t.Helper()
	anchor := anchorFile(t, "GEM.RCA7-TEST-ONLY.der")
	bundle := publishedBundle(t, "ref/ECC-RSA_TSL-ref", "roots-nonprod.json", now, anchor)
	store, err := LoadTrustStore(bundle, anchor, signerAnchorsFor(t, "nonprod"), now, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// A real SMC-B under the real reference list, by every profile, with the CA types the list states.
func TestVALID001ARealSMCBUnderTheRealList(t *testing.T) {
	var corpus validateCorpus
	readJSON(t, pathCorpusDir+"validate.json", &corpus)
	if len(corpus.Real) != len(Profiles()) {
		t.Fatalf("%d cases", len(corpus.Real))
	}
	store := refBundle(t, tslCaptured)
	leaf := certificateAt(t, "../../rust/ti-pki/tests/fixtures/smcb-ee-test-only.pem")
	certType, ok := DetectCertificateType(leaf)
	if !ok {
		t.Fatal("no type")
	}
	for _, want := range corpus.Real {
		validator := LookupProfile(want.Profile).Validator(store, certType, RevocationHardFail)
		result, err := validator.Validate(context.Background(), []*x509.Certificate{leaf}, tslCaptured, newScripted("good"))
		if err != nil {
			t.Fatal(err)
		}
		if got, expected := describeResult(result), describeWantedVerdict(want.Verdict); got != expected {
			t.Errorf("%s:\n got  %s\n want %s", want.Profile, got, expected)
		}
	}
}

// VALID-006 under the real list: it names GEM.TSL-CA28, so its signer stands; with the list's CAs taken out, the
// same CA, supplied and signed by a root, does not.
func TestVALID006ACAUnderTheRealList(t *testing.T) {
	var corpus validateCorpus
	readJSON(t, pathCorpusDir+"validate.json", &corpus)
	store := refBundle(t, tslCaptured)
	ca, err := ParseCertificate(anchorFile(t, "GEM.TSL-CA28-TEST-ONLY.der"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := func(name string) *x509.Certificate {
		return certificateAt(t, "../../rust/ti-pki/tests/fixtures/"+name)
	}
	for _, c := range []struct {
		name      string
		validator *Validator
		leaf      *x509.Certificate
		want      verdictJSON
	}{
		{"the signer", ProfileTslSig.Validator(store, CertTslSig, RevocationHardFail), fixture("tsl-signing-unit-12-test-only.pem"), corpus.Signer},
		{"its OCSP responder", NewValidator(&TrustStore{Roots: store.Roots, CATypes: store.CATypes}), fixture("tsl-ca-ocsp-signer-10-test-only.pem"), corpus.Unlisted},
	} {
		result, err := c.validator.Validate(context.Background(), []*x509.Certificate{c.leaf, ca}, tslCaptured, newScripted("good"))
		if err != nil {
			t.Fatal(err)
		}
		if got, expected := describeResult(result), describeWantedVerdict(c.want); got != expected {
			t.Errorf("%s:\n got  %s\n want %s", c.name, got, expected)
		}
	}
}

// VALID-007 under the real list: both read what it states for every CA, and what that lets the CA of a real SMC-B
// issue.
func TestVALID007TheRealListDecidesWhatACAMayIssue(t *testing.T) {
	var corpus validateCorpus
	readJSON(t, pathCorpusDir+"validate.json", &corpus)
	store := refBundle(t, tslCaptured)
	got := make([]string, 0, len(store.Intermediates))
	for _, intermediate := range store.Intermediates {
		types := oidTexts(store.tslTypesOf(intermediate.Certificate))
		slices.Sort(types)
		got = append(got, fmt.Sprint(intermediate.Certificate.Subject.CommonName, types))
	}
	slices.Sort(got)
	want := make([]string, 0, len(corpus.CATypes))
	for _, entry := range corpus.CATypes {
		types := make([]string, 0, len(entry[1].([]any)))
		for _, oid := range entry[1].([]any) {
			types = append(types, oid.(string))
		}
		want = append(want, fmt.Sprint(entry[0], types))
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("stated types differ:\n got  %v\n want %v", got, want)
	}
	leaf := certificateAt(t, "../../rust/ti-pki/tests/fixtures/smcb-ee-test-only.pem")
	var authorized []string
	for _, certType := range AllCertificateTypes() {
		if certType == CertTslSig {
			continue
		}
		validator := NewValidator(store)
		validator.CertType = certType
		result, err := validator.Validate(context.Background(), []*x509.Certificate{leaf}, tslCaptured, newScripted("good"))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(result.Errors, func(f Finding) bool { return f.Code == "cert_type_ca_not_authorized" }) {
			authorized = append(authorized, string(certType))
		}
	}
	if !slices.Equal(authorized, corpus.Authorized) {
		t.Errorf("authorized %v, want %v", authorized, corpus.Authorized)
	}
}

// VALID-007: no fixture's CA states types in a list ti-pki's test can reach from outside, so these are stated here.
func TestVALID007TheTypesTheListStates(t *testing.T) {
	leaf, issuer := pkiCert(t, "types/type-hci-aut.pem"), pkiCert(t, "sub-ca-komp.pem")
	base := func(types map[string][]x509.OID) *ValidationResult {
		store := &TrustStore{Roots: []*x509.Certificate{pkiCert(t, "rca7.pem")}, Intermediates: []Intermediate{{Certificate: issuer}}, CATypes: types}
		validator := NewValidator(store)
		result, err := validator.Validate(context.Background(), []*x509.Certificate{leaf}, time.Unix(validateNow, 0), newScripted("good"))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := base(nil); !result.Valid || len(result.Warnings) != 0 {
		t.Errorf("no list: %s", describeResult(result))
	}
	if result := base(map[string][]x509.OID{string(issuer.Raw): {CertHciAut.OID()}}); !result.Valid || len(result.Warnings) != 0 {
		t.Errorf("stated: %s", describeResult(result))
	}
	if result := base(map[string][]x509.OID{string(issuer.Raw): {CertFdSig.OID()}}); result.Valid || result.Errors[0].Code != "cert_type_ca_not_authorized" {
		t.Errorf("another type: %s", describeResult(result))
	}
	if result := base(map[string][]x509.OID{}); result.Valid || result.Errors[0].Code != "cert_type_ca_not_authorized" {
		t.Errorf("none stated: %s", describeResult(result))
	}
}

type noting struct{ asked []string }

func (n *noting) Check(_ context.Context, cert, _ *x509.Certificate, _ *TrustStore) (*RevocationResult, error) {
	n.asked = append(n.asked, cert.Subject.CommonName)
	return &RevocationResult{Status: RevocationGood}, nil
}

// VALID-004: the address of a responder is in a certificate an attacker may have made, so it is asked only once
// everything else has passed.
func TestVALID004NoResponderIsAskedForACertificateThatFailed(t *testing.T) {
	store := &TrustStore{Roots: []*x509.Certificate{pkiCert(t, "rca7.pem")}, Intermediates: []Intermediate{{Certificate: pkiCert(t, "sub-ca-komp.pem")}}}
	leaf := pkiCert(t, "types/type-hci-aut.pem")
	checker := &noting{}
	expired := time.Unix(validateNow+10*366*86400, 0)
	result, err := NewValidator(store).Validate(context.Background(), []*x509.Certificate{leaf}, expired, checker)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(checker.asked) != 0 {
		t.Errorf("valid %v, asked about %v", result.Valid, checker.asked)
	}
	forged := tamperedCopy(t, leaf)
	if _, err := NewValidator(store).Validate(context.Background(), []*x509.Certificate{forged}, time.Unix(validateNow, 0), checker); err != nil {
		t.Fatal(err)
	}
	if len(checker.asked) != 0 {
		t.Errorf("asked about a forgery: %v", checker.asked)
	}
	result, err = NewValidator(store).Validate(context.Background(), []*x509.Certificate{leaf}, time.Unix(validateNow, 0), checker)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || len(checker.asked) != 1 {
		t.Errorf("valid %v, asked about %v", result.Valid, checker.asked)
	}
}

// VALID-005: a profile accepts what the certificate shows, whatever the caller wanted of it.
func TestVALID005AProfileRefusesATypeItDoesNotAccept(t *testing.T) {
	store := &TrustStore{Roots: []*x509.Certificate{pkiCert(t, "rca7.pem")}, Intermediates: []Intermediate{{Certificate: pkiCert(t, "sub-ca-komp.pem")}}}
	leaf := pkiCert(t, "types/type-hci-aut.pem")
	run := func(p *Profile, named CertificateType) *ValidationResult {
		result, err := p.Validator(store, named, RevocationDisabled).Validate(context.Background(), []*x509.Certificate{leaf}, time.Unix(validateNow, 0), nil)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := run(ProfileHciAut, CertHciAut); !result.Valid {
		t.Errorf("%s", describeResult(result))
	}
	refused := func(result *ValidationResult) bool {
		return slices.ContainsFunc(result.Errors, func(f Finding) bool { return f.Code == "profile_type_mismatch" })
	}
	for _, p := range []*Profile{ProfileFdTLSS, ProfileTslSig, ProfileIdpdSig} {
		if result := run(p, CertHciAut); !refused(result) {
			t.Errorf("%s: %s", p.Name, describeResult(result))
		}
	}
	if result := run(ProfileIdpdSig, CertFdSig); !refused(result) {
		t.Errorf("a type named by the caller: %s", describeResult(result))
	}
}

// VALID-006: a CA supplied with the certificate, signed by a root, that a verified list does not name.
func TestVALID006ACATheVerifiedListDoesNotNameGivesNoStanding(t *testing.T) {
	leaf, ca := pkiCert(t, "types/type-hci-aut.pem"), pkiCert(t, "sub-ca-komp.pem")
	roots := []*x509.Certificate{pkiCert(t, "rca7.pem")}
	validate := func(store *TrustStore) *ValidationResult {
		validator := NewValidator(store)
		validator.Revocation = RevocationDisabled
		result, err := validator.Validate(context.Background(), []*x509.Certificate{leaf, ca}, time.Unix(validateNow, 0), nil)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	result := validate(&TrustStore{Roots: roots, CATypes: map[string][]x509.OID{}})
	if result.Valid || result.Errors[0].Code != "ca_not_in_tsl" || result.Errors[0].Subject != ca.Subject.CommonName {
		t.Errorf("unlisted: %s", describeResult(result))
	}
	// A list that names the CA but does not keep it, as one withdrawn: the types alone are no standing.
	result = validate(&TrustStore{Roots: roots, CATypes: map[string][]x509.OID{string(ca.Raw): {CertHciAut.OID()}}})
	if result.Valid || result.Errors[0].Code != "ca_not_in_tsl" {
		t.Errorf("withdrawn: %s", describeResult(result))
	}
	listed := &TrustStore{Roots: roots, Intermediates: []Intermediate{{Certificate: ca}}, CATypes: map[string][]x509.OID{string(ca.Raw): {CertHciAut.OID()}}}
	if result := validate(listed); !result.Valid {
		t.Errorf("listed: %s", describeResult(result))
	}
	if result := validate(&TrustStore{Roots: roots}); !result.Valid {
		t.Errorf("no list: %s", describeResult(result))
	}
}

func TestVALIDNoCertificateIsAnError(t *testing.T) {
	if _, err := NewValidator(&TrustStore{}).Validate(context.Background(), nil, time.Now(), newScripted("good")); err == nil {
		t.Error("no certificate")
	}
}

// A checker that is not configured fails closed, as ti-pki's Unchecked does.
func TestVALIDAMissingCheckerFailsClosed(t *testing.T) {
	store := &TrustStore{Roots: []*x509.Certificate{pkiCert(t, "rca7.pem")}, Intermediates: []Intermediate{{Certificate: pkiCert(t, "sub-ca-komp.pem")}}}
	result, err := NewValidator(store).Validate(context.Background(), []*x509.Certificate{pkiCert(t, "types/type-hci-aut.pem")}, time.Unix(validateNow, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Error("valid without a checker")
	}
}
