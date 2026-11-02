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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type walkOutcome struct {
	ParseError   bool     `json:"parse_error"`
	AnchorAbsent bool     `json:"anchor_absent"`
	Trusted      []string `json:"trusted"`
	ForwardStop  *string  `json:"forward_stop"`
	BackwardStop *string  `json:"backward_stop"`
}

type walkCase struct {
	Name    string      `json:"name"`
	Anchor  string      `json:"anchor"`
	Now     int64       `json:"now"`
	JSON    string      `json:"json"`
	File    string      `json:"file"`
	Outcome walkOutcome `json:"outcome"`
}

type rootsCorpus struct {
	Synthetic []walkCase `json:"synthetic"`
	Real      []walkCase `json:"real"`
	Steps     []struct {
		Cross       string `json:"cross"`
		Anchor      string `json:"anchor"`
		Subordinate string `json:"subordinate"`
		Now         int64  `json:"now"`
		Step        *int   `json:"step"`
	} `json:"steps"`
}

// stopKind says where a stop reason came from, in the corpus's words.
func stopKind(stop string) *string {
	if stop == "" {
		return nil
	}
	kind := "other"
	switch {
	case strings.Contains(stop, "A_28419 step "):
		_, rest, _ := strings.Cut(stop, "A_28419 step ")
		kind = rest[:1]
	case strings.Contains(stop, "does not parse"):
		kind = "parse"
	case strings.Contains(stop, "not in roots.json"):
		kind = "absent"
	case strings.Contains(stop, "loops back"):
		kind = "loop"
	}
	return &kind
}

func equalStop(a, b *string) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

func checkWalkCase(t *testing.T, want walkCase, data []byte) {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(want.Anchor)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ParseRoots(data)
	if (err != nil) != want.Outcome.ParseError {
		t.Fatalf("parse: %v, ti-pki parse error %v", err, want.Outcome.ParseError)
	}
	if err != nil {
		return
	}
	walk, err := WalkRoots(anchor, entries, time.Unix(want.Now, 0))
	if (err != nil) != want.Outcome.AnchorAbsent {
		t.Fatalf("walk: %v, ti-pki anchor absent %v", err, want.Outcome.AnchorAbsent)
	}
	if err != nil {
		return
	}
	var got []string
	for _, cert := range walk.Trusted {
		got = append(got, cert.Subject.CommonName)
	}
	if !slices.Equal(got, want.Outcome.Trusted) {
		t.Errorf("trusted %v, ti-pki has %v", got, want.Outcome.Trusted)
	}
	if !equalStop(stopKind(walk.ForwardStop), want.Outcome.ForwardStop) {
		t.Errorf("forward stop %q, ti-pki has %v", walk.ForwardStop, want.Outcome.ForwardStop)
	}
	if !equalStop(stopKind(walk.BackwardStop), want.Outcome.BackwardStop) {
		t.Errorf("backward stop %q, ti-pki has %v", walk.BackwardStop, want.Outcome.BackwardStop)
	}
}

// ROOTS-001, 002: crafted documents, read or refused and walked as in ti-pki.
func TestROOTS001CraftedDocumentsAreWalkedAsInTiPki(t *testing.T) {
	var corpus rootsCorpus
	readJSON(t, pathCorpusDir+"roots.json", &corpus)
	if len(corpus.Synthetic) < 20 {
		t.Fatalf("%d cases", len(corpus.Synthetic))
	}
	for _, want := range corpus.Synthetic {
		t.Run(want.Name, func(t *testing.T) { checkWalkCase(t, want, []byte(want.JSON)) })
	}
}

// ROOTS-002: gematik's real files reach the same roots as in ti-pki, through the RSA ones.
func TestROOTS002TheRealFilesReachTheRootsOfTiPki(t *testing.T) {
	var corpus rootsCorpus
	readJSON(t, pathCorpusDir+"roots.json", &corpus)
	if len(corpus.Real) < 6 {
		t.Fatalf("%d cases", len(corpus.Real))
	}
	for _, want := range corpus.Real {
		t.Run(want.Name+"@"+strconv.FormatInt(want.Now, 10), func(t *testing.T) {
			data, err := os.ReadFile("../../rust/ti-pki/src/" + want.File)
			if err != nil {
				t.Fatal(err)
			}
			checkWalkCase(t, want, data)
		})
	}
}

// ROOTS-003: the failing step, every cross certificate against every root.
func TestROOTS003TheStepThatFailsIsThatOfTiPki(t *testing.T) {
	var corpus rootsCorpus
	readJSON(t, pathCorpusDir+"roots.json", &corpus)
	if len(corpus.Steps) < 100 {
		t.Fatalf("%d cases", len(corpus.Steps))
	}
	certs := pathFixtures(t)
	seen := map[int]bool{}
	for _, want := range corpus.Steps {
		err := VerifyCrossSigned(certs[want.Anchor], certs[want.Cross], certs[want.Subordinate], time.Unix(want.Now, 0))
		var failed *CrossCertError
		switch {
		case want.Step == nil:
			if err != nil {
				t.Errorf("%+v: %v", want, err)
			}
			seen[0] = true
		case !errors.As(err, &failed) || failed.Step != *want.Step:
			t.Errorf("%s/%s/%s@%d: %v, ti-pki fails step %d", want.Cross, want.Anchor, want.Subordinate, want.Now, err, *want.Step)
		default:
			seen[*want.Step] = true
		}
	}
	if !seen[0] {
		t.Error("the corpus has no passing case")
	}
	t.Logf("steps reached: %v", seen)
}

// The rule on RSA lives in one place: a chain link under an RSA key is still refused, while the walk
// takes the real RSA roots, as TestROOTS002TheRealFilesReachTheRootsOfTiPki shows.
func TestROOTS002RSAIsForTheWalkAlone(t *testing.T) {
	rsaRoot, err := ParseCertificate(fixtureDER(t, "rca-rsa.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignedBy(rsaRoot, rsaRoot); err == nil {
		t.Error("a chain link under an RSA key")
	}
}

// No fixture gets past step 4, so these certificates are made here, each breaking one later step.
func TestROOTS003TheLaterStepsAreChecked(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	now := time.Now()
	issue := func(subject string, ski []byte, public *ecdsa.PublicKey, signer *ecdsa.PrivateKey, parent *x509.Certificate) *x509.Certificate {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: subject},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), SubjectKeyId: ski,
			BasicConstraintsValid: true, IsCA: true,
		}
		if parent == nil {
			parent = template
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	anchorKey, subKey, otherKey := newKey(), newKey(), newKey()
	ski := []byte{1, 2, 3}
	anchor := issue("GEM.RCA1", []byte{9}, &anchorKey.PublicKey, anchorKey, nil)
	cross := issue("GEM.RCA2", ski, &subKey.PublicKey, anchorKey, anchor)
	for _, test := range []struct {
		name        string
		subordinate *x509.Certificate
		step        int
	}{
		{"all steps pass", issue("GEM.RCA2", ski, &subKey.PublicKey, subKey, nil), 0},
		{"another common name", issue("GEM.RCA3", ski, &subKey.PublicKey, subKey, nil), 5},
		{"another public key", issue("GEM.RCA2", ski, &otherKey.PublicKey, otherKey, nil), 6},
		{"self-signature under another key", issue("GEM.RCA2", ski, &subKey.PublicKey, otherKey, nil), 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := VerifyCrossSigned(anchor, cross, test.subordinate, now)
			var failed *CrossCertError
			switch {
			case test.step == 0 && err != nil:
				t.Error(err)
			case test.step != 0 && (!errors.As(err, &failed) || failed.Step != test.step):
				t.Errorf("%v, want step %d", err, test.step)
			}
		})
	}
}

func TestROOTS004ABundleForAnotherAnchorIsRefused(t *testing.T) {
	bundle := &Bundle{Label: "x", Roots: []byte("[]")}
	if _, err := TrustedRoots(bundle, AnchorProd, time.Now()); err == nil {
		t.Error("an anchor that is not the bundle's")
	}
	bundle.AnchorSHA256 = sha256.Sum256(AnchorProd)
	if _, err := TrustedRoots(bundle, AnchorProd, time.Now()); err == nil {
		t.Error("an empty roots.json")
	}
}

func TestTheAnchorIsTheOneOfTiPki(t *testing.T) {
	rust, err := os.ReadFile("../../rust/ti-pki/src/anchors/GEM.RCA7.der")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(AnchorProd, rust) {
		t.Error("AnchorProd differs from ti-pki's")
	}
	var cert *x509.Certificate
	if cert, err = ParseCertificate(AnchorProd); err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "GEM.RCA7" {
		t.Error(cert.Subject.CommonName)
	}
}

func FuzzParseRoots(f *testing.F) {
	f.Add([]byte(`[{"cert":"AAAA"}]`))
	f.Add([]byte(`{"roots":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := ParseRoots(data)
		if (err == nil) == (len(entries) == 0) {
			t.Errorf("%d entries, %v", len(entries), err)
		}
	})
}
