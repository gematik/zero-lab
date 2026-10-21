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
	"encoding/base64"
	"errors"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The tests are named after the check of Section 4.3 they prove, TestRFC9449_4_3_<check>.

func TestRFC9449_4_3_00_ValidProofIsAccepted(t *testing.T) {
	k := newTestKey(t)
	proof := mustVerify(t, newTestVerifier(t, Config{}), withProof(k.sign(t, k.header(), validClaims())), testRequest())
	if proof.Thumbprint != k.thumbprint(t) || proof.ID != "e1j3V_bKic8-LAEB" {
		t.Fatalf("proof %+v", proof)
	}
}

func TestRFC9449_4_3_00_MissingProofIsRefused(t *testing.T) {
	_, err := newTestVerifier(t, Config{}).Verify(http.Header{}, testRequest())
	requireRefused(t, err, CodeInvalidProof, "no DPoP proof")
}

// Check 1: "There is not more than one DPoP HTTP request header field."
func TestRFC9449_4_3_01_MoreThanOneDPoPHeaderIsRefused(t *testing.T) {
	k := newTestKey(t)
	proof := k.sign(t, k.header(), validClaims())
	h := http.Header{}
	h.Add(HeaderName, proof)
	h.Add("dpop", proof) // header names are case-insensitive (Section 4.1)
	_, err := newTestVerifier(t, Config{}).Verify(h, testRequest())
	requireRefused(t, err, CodeInvalidProof, "more than one DPoP header")
}

// Check 2: "The DPoP HTTP request header field value is a single and well-formed JWT."
func TestRFC9449_4_3_02_ValueThatIsNotOneJWTIsRefused(t *testing.T) {
	k := newTestKey(t)
	proof := k.sign(t, k.header(), validClaims())
	v := newTestVerifier(t, Config{})
	for name, value := range map[string]string{
		"two proofs joined by a proxy": proof + ", " + proof,
		"JWS JSON serialization":       `{"payload":"e30","signatures":[]}`,
	} {
		_, err := v.Verify(withProof(value), testRequest())
		requireRefused(t, err, CodeInvalidProof, "DPoP header is not a single token68 value")
		_ = name
	}
	for name, value := range map[string]string{
		"not a JWT":            "abc",
		"two segments":         strings.Join(strings.Split(proof, ".")[:2], "."),
		"unsigned payload":     strings.Join(strings.Split(proof, ".")[:2], ".") + ".",
		"payload not a JSON":   encodeSegment(t, k.header()) + "." + base64.RawURLEncoding.EncodeToString([]byte("x")) + ".AA",
		"header not base64url": "!!.e30.AA",
	} {
		_, err := v.Verify(withProof(value), testRequest())
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeInvalidProof {
			t.Errorf("%s: got %v, want invalid_dpop_proof", name, err)
		}
	}
}

func TestRFC9449_4_3_02_OversizedProofIsRefused(t *testing.T) {
	_, err := newTestVerifier(t, Config{MaxSize: 64}).Verify(withProof(strings.Repeat("a", 65)), testRequest())
	requireRefused(t, err, CodeInvalidProof, "DPoP proof too large")
}

// Check 3: "All required claims per Section 4.2 are contained in the JWT", and the header of
// Section 4.2 carries jwk.
func TestRFC9449_4_3_03_MissingRequiredClaimIsRefused(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{})
	for claim, description := range map[string]string{
		"jti": "DPoP proof has no jti",
		"htm": "DPoP proof has no htm",
		"htu": "DPoP proof has no htu",
		"iat": "DPoP proof has no iat",
	} {
		c := validClaims()
		delete(c, claim)
		_, err := v.Verify(withProof(k.sign(t, k.header(), c)), testRequest())
		requireRefused(t, err, CodeInvalidProof, description)
	}
}

// A claim of the wrong type is as good as missing; member names are exact, so "HTU" is not htu.
func TestRFC9449_4_3_03_ClaimsAreTypedAndNamedExactly(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{})
	cases := []struct {
		change      func(map[string]any)
		description string
	}{
		{func(c map[string]any) { c["jti"] = 7 }, "DPoP proof has no jti"},
		{func(c map[string]any) { c["jti"] = "" }, "DPoP proof has no jti"},
		{func(c map[string]any) { delete(c, "htu"); c["HTU"] = testURI }, "DPoP proof has no htu"},
		{func(c map[string]any) { c["iat"] = "1561" }, "DPoP proof iat is not a NumericDate"},
		{func(c map[string]any) { c["iat"] = -1 }, "DPoP proof iat is not a NumericDate"},
		{func(c map[string]any) { c["ath"] = 1 }, "DPoP proof ath is not a string"},
		{func(c map[string]any) { c["nonce"] = true }, "DPoP proof nonce is not a string"},
	}
	for _, tc := range cases {
		c := validClaims()
		tc.change(c)
		_, err := v.Verify(withProof(k.sign(t, k.header(), c)), testRequest())
		requireRefused(t, err, CodeInvalidProof, tc.description)
	}
}

// A NumericDate may have a fraction (RFC 7519 Section 2).
func TestRFC9449_4_3_03_FractionalIatIsAccepted(t *testing.T) {
	k := newTestKey(t)
	c := validClaims()
	c["iat"] = float64(testNow.Unix()) + 0.5
	proof := mustVerify(t, newTestVerifier(t, Config{}), withProof(k.sign(t, k.header(), c)), testRequest())
	if !proof.IssuedAt.Equal(testNow.Add(500 * time.Millisecond)) {
		t.Fatalf("iat %v", proof.IssuedAt)
	}
}

func TestRFC9449_4_3_03_MissingJWKHeaderIsRefused(t *testing.T) {
	k := newTestKey(t)
	h := k.header()
	delete(h, "jwk")
	_, err := newTestVerifier(t, Config{}).Verify(withProof(k.sign(t, h, validClaims())), testRequest())
	requireRefused(t, err, CodeInvalidProof, "DPoP proof has no valid jwk header")
}

// Check 4: "The typ JOSE Header Parameter has the value dpop+jwt."
func TestRFC9449_4_3_04_TypOtherThanDPoPJWTIsRefused(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{})
	for _, typ := range []any{nil, "JWT", "at+jwt", "dpop", 1} {
		h := k.header()
		if typ == nil {
			delete(h, "typ")
		} else {
			h["typ"] = typ
		}
		_, err := v.Verify(withProof(k.sign(t, h, validClaims())), testRequest())
		requireRefused(t, err, CodeInvalidProof, "DPoP proof typ is not dpop+jwt")
	}
}

// typ is a media type: case-insensitive, with "application/" implied (RFC 7515 Section 4.1.9).
func TestRFC9449_4_3_04_TypIsComparedAsAMediaType(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{})
	for _, typ := range []string{"DPoP+JWT", "application/dpop+jwt"} {
		h := k.header()
		h["typ"] = typ
		mustVerify(t, v, withProof(k.sign(t, h, validClaims())), testRequest())
	}
}

// Check 5: alg "indicates a registered asymmetric digital signature algorithm, is not none,
// is supported by the application, and is acceptable per local policy".
func TestRFC9449_4_3_05_NoneMACAndUnacceptedAlgorithmsAreRefused(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{})
	for _, alg := range []string{"none", "HS256", "ES384", "RS256"} {
		h := k.header()
		h["alg"] = alg
		_, err := v.Verify(withProof(k.sign(t, h, validClaims())), testRequest())
		requireRefused(t, err, CodeInvalidProof, "DPoP proof is not a well-formed JWS with an accepted algorithm")
	}
}

// Section 4.2: alg "MUST NOT be none or an identifier for a symmetric algorithm"; a server
// cannot be configured to accept one.
func TestRFC9449_4_3_05_SymmetricAlgorithmCannotBeConfigured(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{"none", jose.HS256, jose.HS512, "", "ES256K"} {
		if _, err := NewVerifier(Config{Algorithms: []jose.SignatureAlgorithm{alg}}); err == nil {
			t.Errorf("%q accepted", alg)
		}
	}
}

// Check 6: "The JWT signature verifies with the public key contained in the jwk JOSE Header
// Parameter."
func TestRFC9449_4_3_06_SignatureByAnotherKeyIsRefused(t *testing.T) {
	k, other := newTestKey(t), newTestKey(t)
	h := k.header()
	h["jwk"] = other.jwk
	_, err := newTestVerifier(t, Config{}).Verify(withProof(k.sign(t, h, validClaims())), testRequest())
	requireRefused(t, err, CodeInvalidProof, "DPoP proof signature does not verify with its jwk")
}

func TestRFC9449_4_3_06_TamperedPayloadIsRefused(t *testing.T) {
	k := newTestKey(t)
	parts := strings.Split(k.sign(t, k.header(), validClaims()), ".")
	c := validClaims()
	c["htu"] = "https://evil.example.test/token"
	parts[1] = encodeSegment(t, c)
	_, err := newTestVerifier(t, Config{}).Verify(withProof(strings.Join(parts, ".")), Request{Method: testMethod, URI: "https://evil.example.test/token"})
	requireRefused(t, err, CodeInvalidProof, "DPoP proof signature does not verify with its jwk")
}

// Check 7: "The jwk JOSE Header Parameter does not contain a private key."
func TestRFC9449_4_3_07_PrivateKeyInJWKIsRefused(t *testing.T) {
	k := newTestKey(t)
	jwk := maps.Clone(k.jwk)
	d, err := k.private.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwk["d"] = base64.RawURLEncoding.EncodeToString(d)
	h := k.header()
	h["jwk"] = jwk
	_, err = newTestVerifier(t, Config{}).Verify(withProof(k.sign(t, h, validClaims())), testRequest())
	requireRefused(t, err, CodeInvalidProof, "DPoP proof jwk contains a private key")
}

// Check 8: "The htm claim matches the HTTP method of the current request." Methods are
// case-sensitive (RFC 9110 Section 9.1).
func TestRFC9449_4_3_08_MethodMismatchIsRefused(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{})
	for _, method := range []string{"GET", "post"} {
		c := validClaims()
		c["htm"] = method
		_, err := v.Verify(withProof(k.sign(t, k.header(), c)), testRequest())
		requireRefused(t, err, CodeInvalidProof, "DPoP proof htm does not match the request method")
	}
}

// Check 9: htu "matches the HTTP URI value for the HTTP request in which the JWT was
// received, ignoring any query and fragment parts."
func TestRFC9449_4_3_09_HtuIgnoresQueryAndFragment(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{})
	c := validClaims()
	c["htu"] = testURI + "?code=abc#section"
	mustVerify(t, v, withProof(k.sign(t, k.header(), c)), Request{Method: testMethod, URI: testURI + "?other=1"})
}

// Section 4.3: "servers SHOULD employ syntax-based normalization (Section 6.2.2 of [RFC3986])
// and scheme-based normalization (Section 6.2.3 of [RFC3986]) before comparing the htu claim."
func TestRFC9449_4_3_09_HtuIsComparedAfterNormalization(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{})
	for _, htu := range []string{
		"HTTPS://AS.Example.TEST/token",           // case of scheme and host (6.2.2.1)
		"https://as.example.test:443/token",       // default port (6.2.3)
		"https://as.example.test:/token",          // empty port (6.2.3)
		"https://as.example.test/%74oken",         // unreserved percent-encoding (6.2.2.2)
		"https://as.example.test/a/../token",      // dot segments (6.2.2.3)
		"https://as.example.test/./token",         // dot segments (6.2.2.3)
		"https://as.example.test/token?#fragment", // empty query, fragment
	} {
		c := validClaims()
		c["htu"] = htu
		if _, err := v.Verify(withProof(k.sign(t, k.header(), c)), testRequest()); err != nil {
			t.Errorf("%s: %v", htu, err)
		}
	}
}

func TestRFC9449_4_3_09_HtuMismatchIsRefused(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{})
	for _, htu := range []string{
		"http://as.example.test/token",       // scheme
		"https://as.example.test:8443/token", // port
		"https://rs.example.test/token",      // host
		"https://as.example.test/Token",      // path case is significant
		"https://as.example.test/token/",     // trailing slash is another path
		"https://user@as.example.test/token", // userinfo is not an http URI (RFC 9110 4.2.4)
		"/token",                             // not absolute
		"urn:example:token",                  // not http
		"https://as.example.test/%2",         // malformed percent-encoding
	} {
		c := validClaims()
		c["htu"] = htu
		_, err := v.Verify(withProof(k.sign(t, k.header(), c)), testRequest())
		requireRefused(t, err, CodeInvalidProof, "DPoP proof htu does not match the request URI")
	}
}

// The expected URI is the server's own configuration: a misconfigured one is the server's
// error, not a refusal of the client's proof.
func TestRFC9449_4_3_09_MisconfiguredRequestURIIsAServerError(t *testing.T) {
	k := newTestKey(t)
	_, err := newTestVerifier(t, Config{}).Verify(withProof(k.sign(t, k.header(), validClaims())), Request{Method: testMethod, URI: "/token"})
	var e *Error
	if err == nil || errors.As(err, &e) {
		t.Fatalf("got %v, want a non-refusal error", err)
	}
}

// Check 10: "If the server provided a nonce value to the client, the nonce claim matches the
// server-provided nonce value." Without or with a stale nonce the server answers
// use_dpop_nonce with a fresh one (Sections 8, 9).
func TestRFC9449_4_3_10_NonceMustMatchServerNonce(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{Nonces: staticNonces{current: "n-current", fresh: "n-fresh"}})

	_, err := v.Verify(withProof(k.sign(t, k.header(), validClaims())), testRequest())
	if e := requireRefused(t, err, CodeUseNonce, "DPoP proof has no nonce"); e.Nonce != "n-fresh" {
		t.Fatalf("nonce %q", e.Nonce)
	}

	c := validClaims()
	c["nonce"] = "n-stale"
	_, err = v.Verify(withProof(k.sign(t, k.header(), c)), testRequest())
	if e := requireRefused(t, err, CodeUseNonce, "DPoP proof nonce is not current"); e.Nonce != "n-fresh" {
		t.Fatalf("nonce %q", e.Nonce)
	}

	c["nonce"] = "n-current"
	if proof := mustVerify(t, v, withProof(k.sign(t, k.header(), c)), testRequest()); proof.Nonce != "n-current" {
		t.Fatalf("nonce %q", proof.Nonce)
	}
}

// Without a nonce source the server provided no nonce, and none is checked.
func TestRFC9449_4_3_10_NonceIsNotCheckedWithoutServerNonces(t *testing.T) {
	k := newTestKey(t)
	c := validClaims()
	c["nonce"] = "anything"
	mustVerify(t, newTestVerifier(t, Config{}), withProof(k.sign(t, k.header(), c)), testRequest())
}

// Check 11: "The creation time of the JWT ... is within an acceptable window (see Section
// 11.1)."
func TestRFC9449_4_3_11_IatOutsideTheWindowIsRefused(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{MaxAge: time.Minute, Leeway: 5 * time.Second})
	at := func(iat time.Time) error {
		c := validClaims()
		c["iat"] = iat.Unix()
		_, err := v.Verify(withProof(k.sign(t, k.header(), c)), testRequest())
		return err
	}
	for _, iat := range []time.Time{testNow, testNow.Add(-time.Minute), testNow.Add(5 * time.Second)} {
		if err := at(iat); err != nil {
			t.Errorf("iat %v: %v", iat, err)
		}
	}
	requireRefused(t, at(testNow.Add(-time.Minute-time.Second)), CodeInvalidProof, "DPoP proof is too old")
	requireRefused(t, at(testNow.Add(6*time.Second)), CodeInvalidProof, "DPoP proof is issued in the future")
}

// Check 12: with an access token, "ensure that the value of the ath claim equals the hash of
// that access token".
func TestRFC9449_4_3_12_AthMustMatchTheAccessToken(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, Config{})
	req := Request{Method: testMethod, URI: testURI, AccessToken: "the-token", Thumbprint: k.thumbprint(t)}

	_, err := v.Verify(withProof(k.sign(t, k.header(), validClaims())), req)
	requireRefused(t, err, CodeInvalidProof, "DPoP proof has no ath")

	c := validClaims()
	c["ath"] = AccessTokenHash("another-token")
	_, err = v.Verify(withProof(k.sign(t, k.header(), c)), req)
	requireRefused(t, err, CodeInvalidProof, "DPoP proof ath does not match the access token")

	c["ath"] = AccessTokenHash("the-token")
	mustVerify(t, v, withProof(k.sign(t, k.header(), c)), req)
}

// Check 12: "confirm that the public key to which the access token is bound matches the
// public key from the DPoP proof", answered as in Figure 16.
func TestRFC9449_4_3_12_AccessTokenMustBeBoundToTheProofKey(t *testing.T) {
	k, other := newTestKey(t), newTestKey(t)
	c := validClaims()
	c["ath"] = AccessTokenHash("the-token")
	proof := withProof(k.sign(t, k.header(), c))
	v := newTestVerifier(t, Config{})

	_, err := v.Verify(proof, Request{Method: testMethod, URI: testURI, AccessToken: "the-token", Thumbprint: other.thumbprint(t)})
	requireRefused(t, err, CodeInvalidToken, "Invalid DPoP key binding")

	_, err = v.Verify(proof, Request{Method: testMethod, URI: testURI, AccessToken: "the-token"})
	requireRefused(t, err, CodeInvalidToken, "access token is not DPoP-bound")
}

// Section 10: a grant bound to a key (dpop_jkt) is only redeemed with a proof by that key.
func TestRFC9449_10_GrantBoundToAnotherKeyIsRefused(t *testing.T) {
	k, other := newTestKey(t), newTestKey(t)
	v := newTestVerifier(t, Config{})
	proof := withProof(k.sign(t, k.header(), validClaims()))
	_, err := v.Verify(proof, Request{Method: testMethod, URI: testURI, Thumbprint: other.thumbprint(t)})
	requireRefused(t, err, CodeInvalidProof, "DPoP proof key is not the key the grant is bound to")
	mustVerify(t, v, proof, Request{Method: testMethod, URI: testURI, Thumbprint: k.thumbprint(t)})
}

// Section 11.1: "In the context of the target URI, servers can store the jti value of each
// DPoP proof for the time window in which the respective DPoP proof JWT would be accepted to
// prevent multiple uses of the same DPoP proof."
func TestRFC9449_11_1_ReplayedProofIsRefused(t *testing.T) {
	k := newTestKey(t)
	cache := NewMemoryReplayCache(10, fixedClock(testNow))
	v := newTestVerifier(t, Config{Replay: cache})
	proof := withProof(k.sign(t, k.header(), validClaims()))
	mustVerify(t, v, proof, testRequest())
	_, err := v.Verify(proof, testRequest())
	requireRefused(t, err, CodeInvalidProof, "DPoP proof was used before")
}

// An invalid proof does not take a place in the replay cache.
func TestRFC9449_11_1_RefusedProofIsNotRemembered(t *testing.T) {
	k := newTestKey(t)
	cache := NewMemoryReplayCache(1, fixedClock(testNow))
	v := newTestVerifier(t, Config{Replay: cache})
	c := validClaims()
	c["htm"] = "GET"
	if _, err := v.Verify(withProof(k.sign(t, k.header(), c)), testRequest()); err == nil {
		t.Fatal("accepted")
	}
	mustVerify(t, v, withProof(k.sign(t, k.header(), validClaims())), testRequest())
}

// A full replay cache fails closed: the proof is refused rather than an accepted one forgotten.
func TestRFC9449_11_1_FullReplayCacheFailsClosed(t *testing.T) {
	cache := NewMemoryReplayCache(1, fixedClock(testNow))
	if seen, err := cache.Seen("a", testNow.Add(time.Minute)); seen || err != nil {
		t.Fatal(seen, err)
	}
	if _, err := cache.Seen("b", testNow.Add(time.Minute)); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("got %v", err)
	}
	later := NewMemoryReplayCache(1, fixedClock(testNow.Add(2*time.Minute)))
	later.entries = cache.entries
	if seen, err := later.Seen("b", testNow.Add(3*time.Minute)); seen || err != nil {
		t.Fatalf("expired entry not swept: %v %v", seen, err)
	}
	if seen, _ := later.Seen("a", testNow.Add(3*time.Minute)); seen {
		t.Fatal("expired entry still seen")
	}
}

// recordingReplay records the identifiers a verifier asks about.
type recordingReplay struct{ ids []string }

func (r *recordingReplay) Seen(id string, _ time.Time) (bool, error) {
	r.ids = append(r.ids, id)
	return false, nil
}

// Section 11.1: a server "should reject DPoP proof JWTs with unnecessarily large jti values
// or store only a hash thereof"; the jti is tracked "in the context of the target URI".
func TestRFC9449_11_1_ReplayCacheStoresAHashInTheContextOfTheURI(t *testing.T) {
	k := newTestKey(t)
	record := &recordingReplay{}
	v := newTestVerifier(t, Config{Replay: record})
	c := validClaims()
	c["jti"] = strings.Repeat("j", 4000)
	mustVerify(t, v, withProof(k.sign(t, k.header(), c)), testRequest())
	c["htu"] = "https://as.example.test/par"
	mustVerify(t, v, withProof(k.sign(t, k.header(), c)), Request{Method: testMethod, URI: "https://as.example.test/par"})
	if len(record.ids) != 2 || record.ids[0] == record.ids[1] {
		t.Fatalf("ids %q", record.ids)
	}
	for _, id := range record.ids {
		if len(id) != 43 || strings.Contains(id, "jjj") {
			t.Fatalf("id %q is not a SHA-256 hash", id)
		}
	}
}
