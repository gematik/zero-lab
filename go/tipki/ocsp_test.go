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
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const ocspNow = 1767225600

type ocspOutcome struct {
	Error         string  `json:"error"`
	Subject       string  `json:"subject"`
	Status        string  `json:"status"`
	Reason        string  `json:"reason"`
	Responder     string  `json:"responder"`
	Embedded      bool    `json:"embedded"`
	Authorization *string `json:"authorization"`
	ProducedAt    *int64  `json:"produced_at"`
	ThisUpdate    *int64  `json:"this_update"`
	NextUpdate    *int64  `json:"next_update"`
	RevokedAt     *int64  `json:"revoked_at"`
}

type ocspCorpus struct {
	Matrix []struct {
		Response string      `json:"response"`
		Cert     string      `json:"cert"`
		Issuer   string      `json:"issuer"`
		Now      int64       `json:"now"`
		Stapled  bool        `json:"stapled"`
		Store    string      `json:"store"`
		Outcome  ocspOutcome `json:"outcome"`
	} `json:"matrix"`
	Mutated []struct {
		Byte    int         `json:"byte"`
		Outcome ocspOutcome `json:"outcome"`
	} `json:"mutated"`
	Requests []struct {
		Cert    string `json:"cert"`
		Issuer  string `json:"issuer"`
		Request string `json:"request"`
	} `json:"requests"`
	Real []struct {
		Response string      `json:"response"`
		Cert     string      `json:"cert"`
		Issuer   string      `json:"issuer"`
		Now      int64       `json:"now"`
		Outcome  ocspOutcome `json:"outcome"`
	} `json:"real"`
}

func pkiCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	return certificateAt(t, "../../rust/ti-pki/tests/pki/"+name)
}

func unixOrNil(at time.Time) *int64 {
	if at.IsZero() {
		return nil
	}
	seconds := at.Unix()
	return &seconds
}

func describeInt(value *int64) string {
	if value == nil {
		return "-"
	}
	return fmt.Sprint(*value)
}

func describeWanted(want ocspOutcome) string {
	if want.Error != "" {
		return "error " + want.Error + " about " + want.Subject
	}
	authorization := ""
	if want.Authorization != nil {
		authorization = *want.Authorization
	}
	return fmt.Sprintf("%s|%s|%s|%v|%s|%s|%s|%s|%s", want.Status, want.Reason, want.Responder, want.Embedded, authorization,
		describeInt(want.ProducedAt), describeInt(want.ThisUpdate), describeInt(want.NextUpdate), describeInt(want.RevokedAt))
}

func describeGot(result *RevocationResult, err error) string {
	if err != nil {
		if failure, ok := errors.AsType[*OCSPError](err); ok {
			return "error " + failure.Code + " about " + failure.Subject
		}
		return "error " + err.Error()
	}
	authorization := ""
	if result.Authorization != nil {
		authorization = result.Authorization.Kind
		if result.Authorization.CA != "" {
			authorization += "|" + result.Authorization.CA + "|" + result.Authorization.TSP
		}
	}
	return fmt.Sprintf("%s|%s|%s|%v|%s|%s|%s|%s|%s", result.Status, result.Reason, result.ResponderName, result.Responder != nil, authorization,
		describeInt(unixOrNil(result.ProducedAt)), describeInt(unixOrNil(result.ThisUpdate)), describeInt(unixOrNil(result.NextUpdate)), describeInt(unixOrNil(result.RevokedAt)))
}

func testStore(t *testing.T, name string) *TrustStore {
	t.Helper()
	if name == "none" {
		return nil
	}
	komp := "TSP A"
	if name == "other_tsp" {
		komp = "TSP B"
	}
	return &TrustStore{
		Roots: []*x509.Certificate{pkiCert(t, "rca1.pem"), pkiCert(t, "rca7.pem")},
		Intermediates: []Intermediate{
			{Certificate: pkiCert(t, "sub-ca-hba.pem"), Provider: "TSP A"},
			{Certificate: pkiCert(t, "sub-ca-komp.pem"), Provider: komp},
		},
	}
}

func checkAt(now int64, stapled bool, store *TrustStore) ResponseCheck {
	check := NewResponseCheck(time.Unix(now, 0))
	check.Stapled, check.Store = stapled, store
	return check
}

// OCSP-001: every response against every certificate, at every time, online and stapled, with every store.
func TestOCSP001EveryResponseIsJudgedAsInTiPki(t *testing.T) {
	var corpus ocspCorpus
	readJSON(t, pathCorpusDir+"ocsp.json", &corpus)
	if len(corpus.Matrix) < 1000 {
		t.Fatalf("%d cases", len(corpus.Matrix))
	}
	stores := map[string]*TrustStore{"none": nil, "same_tsp": testStore(t, "same_tsp"), "other_tsp": testStore(t, "other_tsp")}
	failures := 0
	for _, want := range corpus.Matrix {
		der, err := os.ReadFile("../../rust/ti-pki/tests/pki/ocsp/" + want.Response + ".der")
		if err != nil {
			t.Fatal(err)
		}
		result, err := VerifyResponse(der, pkiCert(t, want.Cert), pkiCert(t, want.Issuer), checkAt(want.Now, want.Stapled, stores[want.Store]))
		if got, expected := describeGot(result, err), describeWanted(want.Outcome); got != expected {
			if failures++; failures <= 12 {
				t.Errorf("%s %s/%s @%d stapled=%v store=%s:\n got  %s\n want %s", want.Response, want.Cert, want.Issuer, want.Now-ocspNow, want.Stapled, want.Store, got, expected)
			}
		}
	}
	if failures > 0 {
		t.Errorf("%d of %d differ", failures, len(corpus.Matrix))
	}
}

// OCSP-002: a good response with any one byte flipped. No flip may be accepted here that ti-pki refuses, and
// a verdict must be the same. Two differences stand, stated rather than hidden:
//
// ti-pki accepts three flips outside what a signature covers, and Go refuses them: the tag of the signature's
// AlgorithmIdentifier, and the unused-bits byte of the response's and of the embedded certificate's signature.
//
// Within the embedded responder certificate both refuse, by different codes, because the parsers differ on
// malformed DER: crypto/x509 gives ocsp_unavailable where x509-cert parses on to ocsp_responder_untrusted.
func TestOCSP002AFlippedByteIsJudgedAsInTiPki(t *testing.T) {
	var corpus ocspCorpus
	readJSON(t, pathCorpusDir+"ocsp.json", &corpus)
	der, err := os.ReadFile("../../rust/ti-pki/tests/pki/ocsp/good.der")
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.Mutated) != len(der) {
		t.Fatalf("%d cases for %d bytes", len(corpus.Mutated), len(der))
	}
	_, _, body, err := parseOuterResponse(der)
	if err != nil {
		t.Fatal(err)
	}
	basic, err := parseBasicResponse(body)
	if err != nil || len(basic.certs) != 1 {
		t.Fatalf("%v, %d certificates", err, len(basic.certs))
	}
	certStart := bytes.Index(der, basic.certs[0].Raw)
	certEnd := certStart + len(basic.certs[0].Raw)
	goStricter := map[int]bool{311: true, 325: true, 782: true}
	leaf, issuer := pkiCert(t, "ee-arzt.pem"), pkiCert(t, "sub-ca-hba.pem")
	codesDiffer := 0
	for _, want := range corpus.Mutated {
		copied := bytes.Clone(der)
		copied[want.Byte] ^= 0x01
		result, err := VerifyResponse(copied, leaf, issuer, checkAt(ocspNow, false, nil))
		got, expected := describeGot(result, err), describeWanted(want.Outcome)
		switch {
		case got == expected:
			if goStricter[want.Byte] {
				t.Errorf("byte %d is listed as a difference and is none: %s", want.Byte, got)
			}
		case goStricter[want.Byte]:
			if err == nil {
				t.Errorf("byte %d: accepted: %s", want.Byte, got)
			}
		case want.Outcome.Error == "":
			t.Errorf("byte %d: a verdict differs:\n got  %s\n want %s", want.Byte, got, expected)
		case err == nil:
			t.Errorf("byte %d: accepted what ti-pki refuses: %s, want %s", want.Byte, got, expected)
		case want.Byte < certStart || want.Byte >= certEnd:
			t.Errorf("byte %d: outside the embedded certificate:\n got  %s\n want %s", want.Byte, got, expected)
		default:
			codesDiffer++
		}
	}
	t.Logf("%d flips, %d refused by another code within the embedded certificate", len(corpus.Mutated), codesDiffer)
}

// OCSP-003: a request is byte for byte the one ti-pki builds.
func TestOCSP003ARequestIsThatOfTiPki(t *testing.T) {
	var corpus ocspCorpus
	readJSON(t, pathCorpusDir+"ocsp.json", &corpus)
	for _, want := range corpus.Requests {
		got, err := OCSPRequest(pkiCert(t, want.Cert), pkiCert(t, want.Issuer))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != want.Request {
			t.Errorf("%s: %x, ti-pki has %s", want.Cert, got, want.Request)
		}
	}
}

// OCSP-004: what gematik's responders really sent.
func TestOCSP004RealResponsesAreJudgedAsInTiPki(t *testing.T) {
	var corpus ocspCorpus
	readJSON(t, pathCorpusDir+"ocsp.json", &corpus)
	for _, want := range corpus.Real {
		der, err := os.ReadFile("../../rust/ti-pki/tests/fixtures/" + want.Response)
		if err != nil {
			t.Fatal(err)
		}
		leaf := certificateAt(t, "../../rust/ti-pki/tests/fixtures/"+want.Cert)
		issuer := certificateAt(t, "../../rust/ti-pki/tests/fixtures/"+want.Issuer)
		result, err := VerifyResponse(der, leaf, issuer, checkAt(want.Now, false, nil))
		if got, expected := describeGot(result, err), describeWanted(want.Outcome); got != expected {
			t.Errorf("%s:\n got  %s\n want %s", want.Response, got, expected)
		}
	}
}

// TSLSIG-040 to 042: the outcomes the live responders, whose signers are good, cannot be recorded for.
func TestTSLSIG041TheSignersStatusStopsTheList(t *testing.T) {
	signer, anchor := signerFixture(t, "signer"), signerFixture(t, "ca")
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct{ answer, code, rule string }{
		{"good", "", ""},
		{"issuer-signed", "", ""},
		{"revoked", "cert_revoked", "TSLSIG-041"},
		{"unknown", "cert_unknown", "TSLSIG-041"},
		{"no-cert-hash", "certhash_extension_missing", "TSLSIG-041"},
		{"wrong-cert-hash", "certhash_mismatch", "TSLSIG-041"},
	} {
		t.Run(test.answer, func(t *testing.T) {
			der, err := os.ReadFile("../../rust/ti-pki/tests/pki/tsl-signer/ocsp/" + test.answer + ".der")
			if err != nil {
				t.Fatal(err)
			}
			verified := &VerifiedTSL{TSL: &TSL{}, Signer: signer, Anchor: anchor, Warnings: []*TSLError{{Code: "no_ocsp_check"}}}
			transport := &fakeTransport{answers: [][]byte{der}}
			checker := checkerAt(transport, &at)
			err = verified.CheckSignerStatus(context.Background(), checker)
			if test.code == "" {
				if err != nil || len(verified.Warnings) != 0 || verified.SignerStatus == nil {
					t.Errorf("%v, warnings %v", err, verified.Warnings)
				}
				return
			}
			var failed *TSLError
			if !errors.As(err, &failed) || failed.Code != test.code || failed.Rule != test.rule {
				t.Errorf("%v, want %s %s", err, test.code, test.rule)
			}
		})
	}
}

type fakeTransport struct {
	answers [][]byte
	err     error
	posts   []string
}

func (f *fakeTransport) Post(_ context.Context, url, contentType, accept string, body []byte) ([]byte, error) {
	f.posts = append(f.posts, url+" "+contentType+" "+accept)
	if f.err != nil {
		return nil, f.err
	}
	if len(f.answers) == 0 {
		return nil, errors.New("no answer left")
	}
	answer := f.answers[0]
	if len(f.answers) > 1 {
		f.answers = f.answers[1:]
	}
	return answer, nil
}

// The fixture certificates name no responder, so every checker test names one.
const testResponder = "http://responder.test/ocsp"

func checkerAt(transport OCSPTransport, now *time.Time) *OCSPChecker {
	checker := NewOCSPChecker(transport)
	checker.Now = func() time.Time { return *now }
	checker.ResponderURL = testResponder
	return checker
}

func goodFixture(t *testing.T) []byte {
	t.Helper()
	der, err := os.ReadFile("../../rust/ti-pki/tests/pki/ocsp/good.der")
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestOCSPCheckerPostsAndVerifies(t *testing.T) {
	leaf, issuer := pkiCert(t, "ee-arzt.pem"), pkiCert(t, "sub-ca-hba.pem")
	now := time.Unix(ocspNow, 0)
	transport := &fakeTransport{answers: [][]byte{goodFixture(t)}}
	checker := checkerAt(transport, &now)
	result, err := checker.Check(context.Background(), leaf, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != RevocationGood || result.ResponderURL != testResponder || result.FromCache {
		t.Errorf("%+v", result)
	}
	want := testResponder + " application/ocsp-request application/ocsp-response"
	if len(transport.posts) != 1 || transport.posts[0] != want {
		t.Errorf("%v", transport.posts)
	}
}

// A_30044 (4): a status error is repeated three times, then the responder rests, and nothing is sent to it.
func TestOCSPStatusErrorsAreRepeatedThenTheResponderRests(t *testing.T) {
	leaf, issuer := pkiCert(t, "ee-arzt.pem"), pkiCert(t, "sub-ca-hba.pem")
	now := time.Unix(ocspNow, 0)
	tryLater := []byte{0x30, 0x03, 0x0a, 0x01, 0x03}
	for name, transport := range map[string]*fakeTransport{
		"unreachable": {err: errors.New("no route")},
		"tryLater":    {answers: [][]byte{tryLater}},
		"garbage":     {answers: [][]byte{[]byte("garbage")}},
	} {
		t.Run(name, func(t *testing.T) {
			checker := checkerAt(transport, &now)
			_, err := checker.Check(context.Background(), leaf, issuer, nil)
			var failure *OCSPError
			if !errors.As(err, &failure) || failure.Code != "ocsp_unavailable" || !strings.Contains(failure.Message, "resting until") {
				t.Fatalf("%v", err)
			}
			if len(transport.posts) != 1+OCSPStatusRetries {
				t.Errorf("%d attempts", len(transport.posts))
			}
			if _, err := checker.Check(context.Background(), leaf, issuer, nil); !errors.As(err, &failure) || !strings.Contains(failure.Message, "rests until") {
				t.Errorf("while resting: %v", err)
			}
			if len(transport.posts) != 1+OCSPStatusRetries {
				t.Errorf("a resting responder was asked: %d", len(transport.posts))
			}
			later := now.Add(OCSPStatusPause)
			checker.Now = func() time.Time { return later }
			_, _ = checker.Check(context.Background(), leaf, issuer, nil)
			if len(transport.posts) != 2*(1+OCSPStatusRetries) {
				t.Errorf("after the pause: %d", len(transport.posts))
			}
		})
	}
}

func TestOCSPAFailedAnswerIsRepeatedUntilOneSucceeds(t *testing.T) {
	leaf, issuer := pkiCert(t, "ee-arzt.pem"), pkiCert(t, "sub-ca-hba.pem")
	now := time.Unix(ocspNow, 0)
	tryLater := []byte{0x30, 0x03, 0x0a, 0x01, 0x03}
	transport := &fakeTransport{answers: [][]byte{tryLater, tryLater, goodFixture(t)}}
	result, err := checkerAt(transport, &now).Check(context.Background(), leaf, issuer, nil)
	if err != nil || result.Status != RevocationGood || len(transport.posts) != 3 {
		t.Errorf("%v %v, %d posts", result, err, len(transport.posts))
	}
}

// A caller giving up is not the responder's fault.
func TestOCSPACancelledCallDoesNotRestTheResponder(t *testing.T) {
	leaf, issuer := pkiCert(t, "ee-arzt.pem"), pkiCert(t, "sub-ca-hba.pem")
	now := time.Unix(ocspNow, 0)
	transport := &fakeTransport{err: errors.New("cancelled")}
	checker := checkerAt(transport, &now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := checker.Check(ctx, leaf, issuer, nil); err == nil {
		t.Fatal("no error")
	}
	if len(transport.posts) != 1 {
		t.Errorf("%d posts", len(transport.posts))
	}
	if _, resting := checker.restingUntil(testResponder, now); resting {
		t.Error("the responder rests")
	}
}

// A_30046 (6): a good result is reused within its bounds, and an unknown one never.
func TestOCSPResultsAreCachedWithinTheirBounds(t *testing.T) {
	leaf, issuer := pkiCert(t, "ee-arzt.pem"), pkiCert(t, "sub-ca-hba.pem")
	now := time.Unix(ocspNow, 0)
	transport := &fakeTransport{answers: [][]byte{goodFixture(t)}}
	checker := checkerAt(transport, &now)
	if _, err := checker.Check(context.Background(), leaf, issuer, nil); err != nil {
		t.Fatal(err)
	}
	later := now.Add(OCSPCacheTTL - time.Second)
	checker.Now = func() time.Time { return later }
	result, err := checker.Check(context.Background(), leaf, issuer, nil)
	if err != nil || !result.FromCache || len(transport.posts) != 1 {
		t.Errorf("%+v %v, %d posts", result, err, len(transport.posts))
	}
	unknown, err := os.ReadFile("../../rust/ti-pki/tests/pki/ocsp/unknown.der")
	if err != nil {
		t.Fatal(err)
	}
	transport = &fakeTransport{answers: [][]byte{unknown}}
	checker = checkerAt(transport, &now)
	for range 2 {
		if _, err := checker.Check(context.Background(), leaf, issuer, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(transport.posts) != 2 {
		t.Errorf("an unknown answer was reused: %d posts", len(transport.posts))
	}
}

func TestOCSPACertificateWithoutAResponderIsUnknown(t *testing.T) {
	now := time.Unix(ocspNow, 0)
	leaf := *pkiCert(t, "ee-arzt.pem")
	leaf.OCSPServer = nil
	transport := &fakeTransport{}
	checker := checkerAt(transport, &now)
	checker.ResponderURL = ""
	result, err := checker.Check(context.Background(), &leaf, pkiCert(t, "sub-ca-hba.pem"), nil)
	if err != nil || result.Status != RevocationUnknown || len(transport.posts) != 0 {
		t.Errorf("%+v %v", result, err)
	}
}

// The revocation table of the module docs, row by row.
func TestRevocationTheTableDecides(t *testing.T) {
	at := time.Unix(ocspNow, 0)
	failure := func(code string) error { return &OCSPError{Code: code, Message: "x"} }
	for _, test := range []struct {
		name         string
		result       *RevocationResult
		err          error
		hard, soft   string
		hardW, softW bool
	}{
		{name: "good", result: &RevocationResult{Status: RevocationGood}},
		{"revoked before", &RevocationResult{Status: RevocationRevoked, RevokedAt: at.Add(-time.Hour)}, nil, "revoked", "revoked", false, false},
		{"revoked at", &RevocationResult{Status: RevocationRevoked, RevokedAt: at}, nil, "revoked", "revoked", false, false},
		{"revoked without a time", &RevocationResult{Status: RevocationRevoked}, nil, "revoked", "revoked", false, false},
		{"revoked after", &RevocationResult{Status: RevocationRevoked, RevokedAt: at.Add(time.Hour)}, nil, "revoked_after_reference_time", "revoked_after_reference_time", true, true},
		{"unknown", &RevocationResult{Status: RevocationUnknown}, nil, "ocsp_unavailable", "ocsp_unavailable", false, true},
		{"unavailable", nil, failure("ocsp_unavailable"), "ocsp_unavailable", "ocsp_unavailable", false, true},
		{"invalid", nil, failure("ocsp_response_invalid"), "ocsp_response_invalid", "ocsp_response_invalid", false, false},
		{"untrusted", nil, failure("ocsp_responder_untrusted"), "ocsp_responder_untrusted", "ocsp_responder_untrusted", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			check := func(mode RevocationMode, code string, warning bool) {
				t.Helper()
				got := ApplyRevocation(mode, "x", test.result, test.err, at)
				switch {
				case code == "" && got != nil:
					t.Errorf("%s: %+v", mode, got)
				case code != "" && (got == nil || got.Finding.Code != code || got.Warning != warning):
					t.Errorf("%s: %+v, want %s warning=%v", mode, got, code, warning)
				}
			}
			check(RevocationHardFail, test.hard, test.hardW)
			check(RevocationSoftFail, test.soft, test.softW)
			check(RevocationDisabled, "", false)
		})
	}
}

func FuzzVerifyResponse(f *testing.F) {
	for _, name := range []string{"good", "revoked", "unknown", "issuer-signed", "foreign-responder"} {
		if der, err := os.ReadFile("../../rust/ti-pki/tests/pki/ocsp/" + name + ".der"); err == nil {
			f.Add(der)
		}
	}
	body, err := os.ReadFile("../../rust/ti-pki/tests/pki/ee-arzt.pem")
	if err != nil {
		f.Fatal(err)
	}
	leaves, err := ParsePEMCertificates(body)
	if err != nil {
		f.Fatal(err)
	}
	body, err = os.ReadFile("../../rust/ti-pki/tests/pki/sub-ca-hba.pem")
	if err != nil {
		f.Fatal(err)
	}
	issuers, err := ParsePEMCertificates(body)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		result, err := VerifyResponse(der, leaves[0], issuers[0], checkAt(ocspNow, false, nil))
		if (result == nil) == (err == nil) {
			t.Errorf("%v %v", result, err)
		}
	})
}
