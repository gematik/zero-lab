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

package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fixedClock is a [Clock] that always tells the same time.
type fixedClock time.Time

func (c fixedClock) Now() time.Time { return time.Time(c) }

// testNow is the time the hand-built proofs are issued and checked at.
var testNow = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

const (
	testMethod = "POST"
	testURI    = "https://as.example.test/token"
)

// testKey is a P-256 key with its public JWK as a JSON object, for hand-built proofs.
type testKey struct {
	private *ecdsa.PrivateKey
	jwk     map[string]any
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jose.JSONWebKey{Key: &private.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatal(err)
	}
	return testKey{private: private, jwk: jwk}
}

func (k testKey) thumbprint(t *testing.T) string {
	t.Helper()
	tp, err := thumbprintOf(jose.JSONWebKey{Key: &k.private.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

// header is the JOSE header of a valid proof by k (Section 4.2).
func (k testKey) header() map[string]any {
	return map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": k.jwk}
}

// claims are the claims of a valid proof for testMethod and testURI at testNow.
func validClaims() map[string]any {
	return map[string]any{"jti": "e1j3V_bKic8-LAEB", "htm": testMethod, "htu": testURI, "iat": testNow.Unix()}
}

// sign builds a compact JWS from header and claims and signs it ES256 with k, without the
// package's own code, so tests can produce proofs the package would never create.
func (k testKey) sign(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	input := encodeSegment(t, header) + "." + encodeSegment(t, claims)
	digest := sha256.Sum256([]byte(input))
	der, err := ecdsa.SignASN1(rand.Reader, k.private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rawECDSA(der, 32)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func encodeSegment(t *testing.T, v map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// withProof is a request header carrying proof as its DPoP header.
func withProof(proof string) http.Header {
	h := http.Header{}
	h.Set(HeaderName, proof)
	return h
}

func newTestVerifier(t *testing.T, config Config) *Verifier {
	t.Helper()
	if config.Clock == nil {
		config.Clock = fixedClock(testNow)
	}
	v, err := NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func testRequest() Request { return Request{Method: testMethod, URI: testURI} }

// requireRefused asserts that err is an *Error with code and description, and returns a copy
// of it for further checks.
func requireRefused(t *testing.T, err error, code, description string) Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got %v, want a refusal %s: %s", err, code, description)
	}
	if e.Code != code || e.Description != description {
		t.Fatalf("got %s: %s, want %s: %s", e.Code, e.Description, code, description)
	}
	return *e
}

// mustVerify is v.Verify of header and req, failing the test on a refusal.
func mustVerify(t *testing.T, v *Verifier, header http.Header, req Request) *Proof {
	t.Helper()
	proof, err := v.Verify(header, req)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	return proof
}

// staticNonces accepts one nonce and hands out another.
type staticNonces struct{ current, fresh string }

func (n staticNonces) Valid(nonce string) bool { return nonce == n.current }
func (n staticNonces) Fresh() (string, error)  { return n.fresh, nil }
