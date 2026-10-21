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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// decodeProof returns the JOSE header and claims of a compact proof, read directly.
func decodeProof(t *testing.T, proof string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("%d segments", len(parts))
	}
	for i, target := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatal(err)
		}
	}
	return header, claims
}

func newKey(t *testing.T) *Key {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Section 4.2: the header carries typ dpop+jwt, an asymmetric alg and the public key as jwk;
// the payload jti, htm, htu without query and fragment, and iat.
func TestRFC9449_4_2_ProofHasTheRequiredHeaderAndClaims(t *testing.T) {
	k := newKey(t)
	proof, err := k.Proof("POST", "https://as.example.test/token?x=1#y", ProofOptions{Clock: fixedClock(testNow)})
	if err != nil {
		t.Fatal(err)
	}
	header, claims := decodeProof(t, proof)
	if header["typ"] != "dpop+jwt" || header["alg"] != "ES256" {
		t.Fatalf("header %v", header)
	}
	jwk, _ := header["jwk"].(map[string]any)
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["x"] == nil || jwk["y"] == nil {
		t.Fatalf("jwk %v", jwk)
	}
	if claims["htm"] != "POST" || claims["htu"] != "https://as.example.test/token" || claims["iat"] != float64(testNow.Unix()) {
		t.Fatalf("claims %v", claims)
	}
	if _, ok := claims["ath"]; ok {
		t.Fatal("ath without an access token")
	}
	if _, ok := claims["nonce"]; ok {
		t.Fatal("nonce without a server nonce")
	}
}

// Section 4.2: jwk "MUST NOT contain a private key".
func TestRFC9449_4_2_ProofJWKHasNoPrivateKeyMembers(t *testing.T) {
	header, _ := decodeProof(t, mustProof(t, newKey(t), ProofOptions{}))
	jwk, _ := header["jwk"].(map[string]any)
	for _, member := range privateKeyMembers {
		if _, ok := jwk[member]; ok {
			t.Errorf("jwk has %q", member)
		}
	}
}

// Section 4.2: jti carries at least 96 bits of pseudorandom data, unique per proof.
func TestRFC9449_4_2_JtiIsRandomAndUnique(t *testing.T) {
	k := newKey(t)
	seen := map[string]bool{}
	for range 100 {
		_, claims := decodeProof(t, mustProof(t, k, ProofOptions{}))
		jti, _ := claims["jti"].(string)
		// rand.Text: 26 characters of base32, 5 bits each.
		if len(jti)*5 < 96 {
			t.Fatalf("jti %q has fewer than 96 bits", jti)
		}
		if seen[jti] {
			t.Fatalf("jti %q repeated", jti)
		}
		seen[jti] = true
	}
}

// Sections 4.2 and 7.1: with an access token the proof carries its hash as ath; with a server
// nonce, the nonce.
func TestRFC9449_4_2_ProofCarriesAthAndNonce(t *testing.T) {
	_, claims := decodeProof(t, mustProof(t, newKey(t), ProofOptions{AccessToken: rfcAccessToken, Nonce: "eyJ7S_zG.eyJH0-Z.HX4w-7v"}))
	if claims["ath"] != rfcATH || claims["nonce"] != "eyJ7S_zG.eyJH0-Z.HX4w-7v" {
		t.Fatalf("claims %v", claims)
	}
}

func TestRFC9449_4_2_InvalidProofInputIsRefused(t *testing.T) {
	k := newKey(t)
	proof := func(method, target string, opts ProofOptions) func() error {
		return func() error { _, err := k.Proof(method, target, opts); return err }
	}
	for name, call := range map[string]func() error{
		"method not a token (RFC 9110 9.1)":       proof("GE T", testURI, ProofOptions{}),
		"relative target":                         proof("GET", "/token", ProofOptions{}),
		"non-http target":                         proof("GET", "ws://as.example.test/", ProofOptions{}),
		"userinfo in target (RFC 9110 4.2.4)":     proof("GET", "https://u@as.example.test/", ProofOptions{}),
		"nonce not 1*NQCHAR (8.1)":                proof("GET", testURI, ProofOptions{Nonce: "a b"}),
		"access token not token68 (7.1, Fig. 12)": func() error { return k.Sign(mustRequest(t), ProofOptions{AccessToken: "a b"}) },
	} {
		if call() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every proof the package signs is accepted by its verifier, for each supported key type.
func TestRFC9449_4_2_ProofsOfEveryKeyTypeVerify(t *testing.T) {
	signers := map[jose.SignatureAlgorithm]crypto.Signer{}
	for alg, curve := range map[jose.SignatureAlgorithm]elliptic.Curve{jose.ES256: elliptic.P256(), jose.ES384: elliptic.P384(), jose.ES512: elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signers[alg] = key
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signers[jose.EdDSA] = ed
	v := newTestVerifier(t, Config{Algorithms: []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}})
	for alg, signer := range signers {
		k, err := NewKeyFromSigner(signer)
		if err != nil {
			t.Fatal(err)
		}
		if k.Algorithm() != string(alg) {
			t.Fatalf("%s: key signs %s", alg, k.Algorithm())
		}
		proof, err := k.Proof("GET", "https://rs.example.test/x", ProofOptions{AccessToken: "t", Clock: fixedClock(testNow)})
		if err != nil {
			t.Fatal(err)
		}
		got := mustVerify(t, v, withProof(proof), Request{Method: "GET", URI: "https://rs.example.test/x", AccessToken: "t", Thumbprint: k.Thumbprint()})
		if got.Thumbprint != k.Thumbprint() {
			t.Fatalf("%s: thumbprint", alg)
		}
	}
}

// Section 4.2: the key is asymmetric; this package signs with ECDSA and Ed25519 keys only.
func TestRFC9449_4_2_UnsupportedKeysAreRefused(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, signer := range []crypto.Signer{rsaKey, p224} {
		if _, err := NewKeyFromSigner(signer); err == nil {
			t.Errorf("%T accepted", signer.Public())
		}
	}
}

// Section 4.3 check 1 and Section 7.1: Sign leaves exactly one DPoP header and sends the
// access token in the DPoP scheme.
func TestRFC9449_7_1_SignSetsOneProofAndTheDPoPScheme(t *testing.T) {
	k := newKey(t)
	req := mustRequest(t)
	req.Header.Set(HeaderName, "stale")
	if err := k.Sign(req, ProofOptions{AccessToken: rfcAccessToken, Clock: fixedClock(testNow)}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Values(HeaderName); len(got) != 1 || got[0] == "stale" {
		t.Fatalf("DPoP headers %v", got)
	}
	if got := req.Header.Get("Authorization"); got != "DPoP "+rfcAccessToken {
		t.Fatalf("Authorization %q", got)
	}
	token, err := AccessToken(req.Header)
	if err != nil || token != rfcAccessToken {
		t.Fatalf("AccessToken %q, %v", token, err)
	}
	mustVerify(t, newTestVerifier(t, Config{}), req.Header, Request{Method: "GET", URI: req.URL.String(), AccessToken: token, Thumbprint: k.Thumbprint()})
}

// Section 6.1: the key's thumbprint is its RFC 7638 JWK SHA-256 thumbprint, base64url.
func TestRFC9449_6_1_ThumbprintIsTheJWKSHA256Thumbprint(t *testing.T) {
	k := newKey(t)
	public := k.Public()
	sum, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if k.Thumbprint() != base64.RawURLEncoding.EncodeToString(sum) {
		t.Fatal("thumbprint")
	}
}

func mustProof(t *testing.T, k *Key, opts ProofOptions) string {
	t.Helper()
	proof, err := k.Proof("GET", testURI, opts)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func mustRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://rs.example.test/resource?id=7", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
