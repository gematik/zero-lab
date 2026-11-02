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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const detachedDir = "../../spec/tsl-detached/testdata/"

var tslCaptured = time.Date(2026, 11, 1, 16, 47, 42, 0, time.UTC)

func readDetached(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(detachedDir + name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func anchorFile(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile("anchors/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func signerAnchorsFor(t *testing.T, env string) [][]byte {
	t.Helper()
	if env == "prod" {
		return [][]byte{anchorFile(t, "GEM.TSL-CA3.der")}
	}
	return [][]byte{anchorFile(t, "GEM.TSL-CA28-TEST-ONLY.der")}
}

// TSLDET-001 to 006, TSLSIG-031: the corpus of spec/tsl-detached, as its CONFORMANCE.md asks. The entries
// whose result rests on the signer's status wait for stage 4 of TASK-176, and show as skipped.
func TestTSLDETTheManifestIsMet(t *testing.T) {
	var manifest []struct {
		Path         string  `json:"path"`
		Signature    string  `json:"signature"`
		SignerStatus *string `json:"signer_status"`
		Time         string  `json:"time"`
		Env          string  `json:"env"`
		Expect       struct {
			Result         string   `json:"result"`
			Code           *string  `json:"code"`
			Rule           *string  `json:"rule"`
			Warnings       []string `json:"warnings"`
			SequenceNumber uint64   `json:"sequence_number"`
		} `json:"expect"`
	}
	readJSON(t, detachedDir+"manifest.json", &manifest)
	if len(manifest) < 15 {
		t.Fatalf("%d entries", len(manifest))
	}
	for _, entry := range manifest {
		name := entry.Path + " " + entry.Signature
		if entry.SignerStatus != nil {
			name += " " + *entry.SignerStatus
		}
		t.Run(name, func(t *testing.T) {
			if entry.SignerStatus != nil {
				t.Skip("SKIPPED, NOT VERIFIED: the signer's status comes with stage 4 of TASK-176")
			}
			now, err := time.Parse(time.RFC3339, entry.Time)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyTSL(readDetached(t, entry.Path), readDetached(t, entry.Signature), signerAnchorsFor(t, entry.Env), now, 0)
			if entry.Expect.Result == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if verified.TSL.SequenceNumber != entry.Expect.SequenceNumber {
					t.Errorf("sequence %d", verified.TSL.SequenceNumber)
				}
				var warnings []string
				for _, warning := range verified.Warnings {
					warnings = append(warnings, warning.Code)
				}
				if !equalStrings(warnings, entry.Expect.Warnings) {
					t.Errorf("warnings %v, want %v", warnings, entry.Expect.Warnings)
				}
				return
			}
			var failed *TSLError
			if !errors.As(err, &failed) || failed.Code != *entry.Expect.Code || failed.Rule != *entry.Expect.Rule {
				t.Errorf("%v, want %s %s", err, *entry.Expect.Code, *entry.Expect.Rule)
			}
		})
	}
}

func signerFixture(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	return certificateAt(t, "../../rust/ti-pki/tests/pki/tsl-signer/"+name+".pem")
}

func certificateAt(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParsePEMCertificates(body)
	if err != nil || len(certs) == 0 {
		t.Fatalf("%s: %v", path, err)
	}
	return certs[0]
}

// TSLSIG-031 to 035, the table of ti-pki's unit tests over the same fixtures.
func TestTSLSIGTheSignerIsCheckedAsInTiPki(t *testing.T) {
	anchor := signerFixture(t, "ca")
	at := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := checkTSLSigner(signerFixture(t, "signer"), anchor, at); err != nil {
		t.Error(err)
	}
	for _, test := range []struct{ fixture, code, rule string }{
		{"signer-aki-different", "authoritykeyid_different", "TSLSIG-031"},
		{"signer-ku-extra", "wrong_keyusage", "TSLSIG-033"},
		{"signer-eku-extra", "wrong_extendedkeyusage", "TSLSIG-034"},
		{"signer-no-policy", "tsl_signer_profile_violation", "TSLSIG-035"},
		{"signer-ca", "tsl_signer_profile_violation", "TSLSIG-035"},
		{"signer-no-aia", "tsl_signer_profile_violation", "TSLSIG-035"},
		{"signer-p256", "tsl_signer_profile_violation", "TSLSIG-035"},
		{"signer-sha384", "tsl_signer_profile_violation", "TSLSIG-035"},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			var failed *TSLError
			err := checkTSLSigner(signerFixture(t, test.fixture), anchor, at)
			if !errors.As(err, &failed) || failed.Code != test.code || failed.Rule != test.rule {
				t.Errorf("%v, want %s %s", err, test.code, test.rule)
			}
		})
	}
	for _, when := range []time.Time{time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 1, 0, time.UTC)} {
		var failed *TSLError
		err := checkTSLSigner(signerFixture(t, "signer"), anchor, when)
		if !errors.As(err, &failed) || failed.Rule != "TSLSIG-032" {
			t.Errorf("%s: %v", when, err)
		}
	}
	for _, when := range []time.Time{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if err := checkTSLSigner(signerFixture(t, "signer"), anchor, when); err != nil {
			t.Errorf("%s: %v", when, err)
		}
	}
	// The fixture's real issuer, by name, key identifier and signature.
	if err := checkTSLSigner(signerFixture(t, "signer-aki-different"), signerFixture(t, "ca-same-name"), at); err != nil {
		t.Errorf("under its own issuer: %v", err)
	}
	// Everything but the signature fits, which alone tells.
	tampered := tamperedCopy(t, signerFixture(t, "signer"))
	var failed *TSLError
	err := checkTSLSigner(tampered, anchor, at)
	if !errors.As(err, &failed) || failed.Code != "certificate_not_valid_math" || failed.Rule != "TSLSIG-031" {
		t.Errorf("a tampered signature: %v", err)
	}
}

// ti-pki finds a compressed key at TSLSIG-035; go/brainpool takes uncompressed points only, so it never
// gets that far. Both refuse.
func TestTSLSIG035ACompressedKeyIsRefusedAtParsing(t *testing.T) {
	body, err := os.ReadFile("../../rust/ti-pki/tests/pki/tsl-signer/signer-compressed-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePEMCertificates(body); err == nil {
		t.Error("a compressed key parsed")
	}
}

func hexSum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestTSLThePublishedListsReadAsInTiPki(t *testing.T) {
	var corpus struct {
		Lists []struct {
			Name           string `json:"name"`
			Stem           string `json:"stem"`
			ID             string `json:"id"`
			SequenceNumber uint64 `json:"sequence_number"`
			IssuedAt       int64  `json:"issued_at"`
			NextUpdate     *int64 `json:"next_update"`
			Production     bool   `json:"production"`
			SchemeSHA256   string `json:"scheme_sha256"`
			Primary        string `json:"primary"`
			Backup         string `json:"backup"`
			Sequence       []struct {
				ID     string `json:"id"`
				Number uint64 `json:"number"`
				Result string `json:"result"`
			} `json:"sequence"`
			Services            int    `json:"services"`
			ServicesSHA256      string `json:"services_sha256"`
			Skipped             int    `json:"skipped"`
			Intermediates       int    `json:"intermediates"`
			IntermediatesSHA256 string `json:"intermediates_sha256"`
			Kept                []struct {
				SHA256    string `json:"sha256"`
				Signature string `json:"signature"`
			} `json:"kept"`
			Rejected []struct {
				SHA256 string `json:"sha256"`
				Reason string `json:"reason"`
			} `json:"rejected"`
		} `json:"lists"`
	}
	readJSON(t, pathCorpusDir+"tsl.json", &corpus)
	if len(corpus.Lists) != 3 {
		t.Fatalf("%d lists", len(corpus.Lists))
	}
	for _, want := range corpus.Lists {
		t.Run(want.Name, func(t *testing.T) {
			env, rootsFile, anchorName := "nonprod", "roots-nonprod.json", "GEM.RCA7-TEST-ONLY.der"
			if want.Name == "prod" {
				env, rootsFile, anchorName = "prod", "roots-prod.json", "GEM.RCA7.der"
			}
			verified, err := VerifyTSL(readDetached(t, want.Stem+".xml"), readDetached(t, want.Stem+".sig"), signerAnchorsFor(t, env), tslCaptured, 0)
			if err != nil {
				t.Fatal(err)
			}
			tsl := verified.TSL
			if tsl.ID != want.ID || tsl.SequenceNumber != want.SequenceNumber || tsl.IssuedAt.Unix() != want.IssuedAt ||
				want.NextUpdate == nil || tsl.NextUpdate.Unix() != *want.NextUpdate || tsl.Skipped != want.Skipped {
				t.Errorf("%+v", tsl)
			}
			if verified.Production != want.Production {
				t.Errorf("production %v", verified.Production)
			}
			if got := schemeLines(tsl.Scheme); hexSum([]byte(strings.Join(got, "\n"))) != want.SchemeSHA256 {
				t.Errorf("the scheme information differs: %q", got)
			}
			if tsl.Scheme.PrimaryLocation() != want.Primary || tsl.Scheme.BackupLocation() != want.Backup {
				t.Errorf("locations %q %q", tsl.Scheme.PrimaryLocation(), tsl.Scheme.BackupLocation())
			}
			for _, stored := range want.Sequence {
				state := &TSLState{ID: stored.ID, SequenceNumber: stored.Number}
				if stored.ID == "" {
					state = nil
				}
				sequence, err := verified.CheckSequence(state)
				got := map[Sequence]string{SequenceNewer: "newer", SequenceSame: "same"}[sequence]
				if failed, ok := errors.AsType[*TSLError](err); ok {
					got = failed.Code
				}
				if got != stored.Result {
					t.Errorf("against %+v: %s", stored, got)
				}
			}
			var lines []string
			for _, s := range tsl.Services {
				start, fingerprint := int64(0), ""
				if !s.StatusStartingTime.IsZero() {
					start = s.StatusStartingTime.Unix()
				}
				if s.Certificate != nil {
					fingerprint = hexSum(s.Certificate.Raw)
				}
				lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s|%s", s.Provider, s.Name, s.ServiceType, s.Status, start, fingerprint,
					strings.Join(s.SupplyPoints, ","), strings.Join(s.TypeOIDs, ",")))
			}
			if len(lines) != want.Services || hexSum([]byte(strings.Join(lines, "\n"))) != want.ServicesSHA256 {
				t.Errorf("%d services, ti-pki has %d, or they differ", len(lines), want.Services)
			}
			candidates := tsl.IntermediateCAs()
			lines = nil
			for _, c := range candidates {
				since := int64(0)
				if !c.RevokedSince.IsZero() {
					since = c.RevokedSince.Unix()
				}
				lines = append(lines, fmt.Sprintf("%s|%s|%d", hexSum(c.Certificate.Raw), c.Provider, since))
			}
			if len(lines) != want.Intermediates || hexSum([]byte(strings.Join(lines, "\n"))) != want.IntermediatesSHA256 {
				t.Errorf("%d intermediates, ti-pki has %d, or they differ", len(lines), want.Intermediates)
			}

			rootsData, err := os.ReadFile("../../rust/ti-pki/src/" + rootsFile)
			if err != nil {
				t.Fatal(err)
			}
			anchor, err := ParseCertificate(anchorFile(t, anchorName))
			if err != nil {
				t.Fatal(err)
			}
			entries, err := ParseRoots(rootsData)
			if err != nil {
				t.Fatal(err)
			}
			walk, err := WalkRoots(anchor, entries, tslCaptured)
			if err != nil {
				t.Fatal(err)
			}
			kept, rejected := MatchToRoots(candidates, walk.Trusted)
			var gotKept []string
			for _, c := range kept {
				gotKept = append(gotKept, hexSum(c.Certificate.Raw))
			}
			var wantKept []string
			for _, k := range want.Kept {
				wantKept = append(wantKept, k.SHA256)
			}
			if !slices.Equal(gotKept, wantKept) {
				t.Errorf("%d kept, ti-pki keeps %d", len(gotKept), len(wantKept))
			}
			if len(rejected) != len(want.Rejected) {
				t.Errorf("%d rejected, ti-pki rejects %d", len(rejected), len(want.Rejected))
			}
			for i, r := range rejected {
				if i < len(want.Rejected) && hexSum(r.Intermediate.Certificate.Raw) != want.Rejected[i].SHA256 {
					t.Errorf("rejected %d differs", i)
				}
			}
			t.Logf("%s: %d services, %d candidates, %d kept, %d rejected", want.Name, len(tsl.Services), len(candidates), len(kept), len(rejected))
		})
	}
}

func schemeLines(s SchemeInfo) []string {
	lines := []string{fmt.Sprintf("%d|%s|%s|%s", s.VersionIdentifier, s.TSLType, s.SchemeName, s.OperatorName)}
	for _, a := range s.PostalAddresses {
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s", a.Street, a.PostalCode, a.Locality, a.State, a.Country))
	}
	lines = append(lines, strings.Join(s.ElectronicAddresses, ","))
	for _, p := range s.Pointers {
		lines = append(lines, p.Location+"|"+strings.Join(p.AdditionalInformation, ","))
	}
	return lines
}

// TSLSIG-060: a CA the list announces is warned of, unless it is configured already, and never adopted.
func TestTSLSIG060AnAnnouncedAnchorIsWarnedOf(t *testing.T) {
	configured := signerFixture(t, "ca")
	other := signerFixture(t, "ca-same-name")
	tsl := &TSL{Services: []Service{
		{ServiceType: serviceTypeCAPKC, Certificate: other},
		{ServiceType: serviceTypeTSLCertChange, Certificate: configured},
		{ServiceType: serviceTypeTSLCertChange, Certificate: other, Name: "new"},
		{ServiceType: serviceTypeTSLCertChange, Name: "none"},
	}}
	warnings := announcedAnchors(tsl, []*x509.Certificate{configured})
	if len(warnings) != 2 {
		t.Fatalf("%v", warnings)
	}
	for _, warning := range warnings {
		if warning.Code != "tsl_anchor_announced" || warning.Rule != "TSLSIG-060" {
			t.Errorf("%v", warning)
		}
	}
}

// TSLSIG-053: below the minimum, which no published list is.
func TestTSLSIG053ANumberBelowTheMinimumIsRefused(t *testing.T) {
	verified := &VerifiedTSL{TSL: &TSL{ID: "x", SequenceNumber: MinSequenceNumber - 1}}
	var failed *TSLError
	if _, err := verified.CheckSequence(nil); !errors.As(err, &failed) || failed.Code != "tsl_id_incorrect" {
		t.Errorf("%v", err)
	}
}

func publishedBundle(t *testing.T, stem, rootsFile string, fetchedAt time.Time, anchor []byte) *Bundle {
	t.Helper()
	roots, err := os.ReadFile("../../rust/ti-pki/src/" + rootsFile)
	if err != nil {
		t.Fatal(err)
	}
	return &Bundle{
		Label: "test", AnchorSHA256: sha256.Sum256(anchor), Roots: roots,
		TSL: readDetached(t, stem+".xml"), TSLSignature: readDetached(t, stem+".sig"), FetchedAt: fetchedAt,
	}
}

func TestBUNDLE003ABundleTooOldIsRefused(t *testing.T) {
	bundle := publishedBundle(t, "prod/ECC-RSA_TSL", "roots-prod.json", tslCaptured.Add(-24*time.Hour), AnchorProd)
	if _, err := LoadTrustStore(bundle, AnchorProd, [][]byte{TSLSignerAnchorProd}, tslCaptured, 0, nil); err == nil {
		t.Error("a bundle 24 h old")
	}
	bundle.FetchedAt = tslCaptured.Add(-23 * time.Hour)
	store, err := LoadTrustStore(bundle, AnchorProd, [][]byte{TSLSignerAnchorProd}, tslCaptured, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !store.TSL.Production {
		t.Error("the production list is not marked so")
	}
	state := store.TSL.State()
	if _, err := LoadTrustStore(bundle, AnchorProd, [][]byte{TSLSignerAnchorProd}, tslCaptured, 0, &state); err != nil {
		t.Errorf("the same list again: %v", err)
	}
	newer := TSLState{ID: "another", SequenceNumber: state.SequenceNumber + 1}
	if _, err := LoadTrustStore(bundle, AnchorProd, [][]byte{TSLSignerAnchorProd}, tslCaptured, 0, &newer); err == nil {
		t.Error("an older list than the one in use")
	}
	if len(store.Roots) != 10 || len(store.Certificates()) == 0 {
		t.Errorf("%d roots, %d CAs", len(store.Roots), len(store.Certificates()))
	}
}

// TSLSIG-054: a list past its NextUpdate does not load, and within a grace period it warns.
func TestTSLSIG054AListPastItsNextUpdate(t *testing.T) {
	list, sig := readDetached(t, "prod/ECC-RSA_TSL.xml"), readDetached(t, "prod/ECC-RSA_TSL.sig")
	anchors := [][]byte{TSLSignerAnchorProd}
	verified, err := VerifyTSL(list, sig, anchors, tslCaptured, 0)
	if err != nil {
		t.Fatal(err)
	}
	after := verified.TSL.NextUpdate
	var failed *TSLError
	if _, err := VerifyTSL(list, sig, anchors, after, 0); !errors.As(err, &failed) || failed.Code != "validity_warning_2" {
		t.Errorf("at NextUpdate: %v", err)
	}
	verified, err = VerifyTSL(list, sig, anchors, after, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Warnings[0].Code != "validity_warning_1" {
		t.Errorf("%v", verified.Warnings[0])
	}
}

// TSLDET-006: the limit comes before any work.
func TestTSLDET006AnOversizedListIsRefused(t *testing.T) {
	var failed *TSLError
	_, err := VerifyTSL(make([]byte, MaxTSLLen+1), nil, nil, tslCaptured, 0)
	if !errors.As(err, &failed) || failed.Rule != "TSLDET-006" {
		t.Errorf("%v", err)
	}
}

func FuzzParseDetachedSignature(f *testing.F) {
	for _, name := range []string{"prod/ECC-RSA_TSL.sig", "derived/ref-truncated.sig", "derived/ref-unused-bits.sig", "derived/ref-wrong-algorithm.sig"} {
		if body, err := os.ReadFile(detachedDir + name); err == nil {
			f.Add(body)
		}
	}
	f.Fuzz(func(t *testing.T, sig []byte) {
		parsed, err := ParseDetachedSignature(sig)
		if (parsed == nil) != (err != nil) {
			t.Errorf("%v %v", parsed, err)
		}
	})
}

func FuzzParseTSL(f *testing.F) {
	f.Add([]byte(`<TrustServiceStatusList Id="x"><SchemeInformation><TSLSequenceNumber>1</TSLSequenceNumber><ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime></SchemeInformation></TrustServiceStatusList>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		list, err := parseTSL(data)
		if (list == nil) != (err != nil) {
			t.Errorf("%v %v", list, err)
		}
	})
}
