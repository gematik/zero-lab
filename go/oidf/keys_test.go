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

package oidf

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// A relying party's default kid is what it registered with the federation master, so the thumbprint must not change
// with the library behind it. The expected values are golden, computed by an independent implementation (jwx v3.3.0)
// over these very keys. rfc7638 is the example of RFC 7638 section 3.1, "leading zero" has an x with a leading zero byte.
func TestThumbprintsAreByteIdenticalToThePublishedOnes(t *testing.T) {
	for _, tc := range []struct{ name, jwk, want string }{
		{
			"rfc7638",
			`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`,
			"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		},
		{
			"federation master, members besides the key's do not count",
			`{"kty":"EC","crv":"P-256","x":"cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs","y":"XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw","kid":"puk_fedmaster_sig","use":"sig","alg":"ES256"}`,
			"mBeLmGzyijl63cemilA88k7zU7BuYaXEhbRCKqrHLWk",
		},
		{
			"P-256 private key",
			`{"crv":"P-256","d":"Pn9q2dmPV8y9VnWFycf7fQDrR-h5Uh-a8VWjamfZn58","kty":"EC","x":"YDnAaDYvsBz6QKYOj0CUYSeydmD1QHL5pUl-aMu6cA0","y":"ovzYSeBnMCmZYWZZtKcGaABqaPs_ecWDXJ8H5bqHOVA"}`,
			"TIpFu8A7dqbCgaggj6bhur7N0PYzhD6DzW_aR8IutpU",
		},
		{
			"P-256 leading zero",
			`{"crv":"P-256","kty":"EC","x":"AA628i2-zbSIwuZNQ8naY8aAuO18vSUUaf8PT3hqlGg","y":"qRD5X4H1hc000I9MIwFeWWuEtWxohnGUDJkX9uRca5U"}`,
			"DP_wvnb6NYqVMs8bgAVJom1mJcBiffKYJfL124V4ieg",
		},
		{
			"P-384",
			`{"crv":"P-384","kty":"EC","x":"QVvxNlwnf7nyxP6syR-1kZ9pFJs0n2YydSN9YhvEAaEhqZh11gHvy5DfZwG7bXG6","y":"yBbusWYTjMnHmyPCeRHyB1q4EVwCvocdtf24RNhKRUz4Jhjrq46WUBpkKtNElCep"}`,
			"6a90n9Ds0e60duuJJzEFRWXJICgOeIbtvbqs4ux7uO4",
		},
		{
			"P-521",
			`{"crv":"P-521","kty":"EC","x":"AdUb9t4arOFy4I8Ju9qZ2hfhzBDb1ZcZIuEP5wa4aUQ1hi1_20T9W6dpjzH47_X8eMTD02r7hDuIZnGYfLUQDWoq","y":"AeRML_aPH7Ln3MFtTF8jVYtku8W_QiqQiiPHIZGu5F_S_vdB7kycSlNf-HlfdO9t9MrelkloMpKRmgduNVI2ouXa"}`,
			"EmRtAygk-3RAZ6S89onRxh5ye7ImCZV-VznUuZPw9mg",
		},
		{
			"Ed25519",
			`{"crv":"Ed25519","kty":"OKP","x":"zEaxgZq_7EAScjaPMwZvdcTbWTQtNLKmAhaK1mZNjWk"}`,
			"oy-ABExtAH4ay7GHeP56o64yPCpNAwhnzIkq-BWjd64",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk, err := NewJwkFromJSON(tc.jwk)
			if err != nil {
				t.Fatal(err)
			}
			sum, err := jwk.Key.Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			if got := base64.RawURLEncoding.EncodeToString(sum); got != tc.want {
				t.Errorf("thumbprint = %s, want %s", got, tc.want)
			}
		})
	}
}

func writeTestKeyPEM(t *testing.T, curve elliptic.Curve) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, key
}

func TestLoadKeyConfigDefaultsTheKidToTheThumbprint(t *testing.T) {
	path, key := writeTestKeyPEM(t, elliptic.P256())
	_, public, kid, err := loadKeyConfig(KeyConfig{KeyPEMPath: path}, "", keyUseSign)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := (&jose.JSONWebKey{Key: key.Public()}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.RawURLEncoding.EncodeToString(sum); kid != want || public.KeyID != want {
		t.Errorf("kid = %s, public kid = %s, want %s", kid, public.KeyID, want)
	}
}

func TestLoadKeyConfigTakesTheConfiguredKid(t *testing.T) {
	path, _ := writeTestKeyPEM(t, elliptic.P256())
	_, public, kid, err := loadKeyConfig(KeyConfig{KeyPEMPath: path, Kid: "registered"}, "", keyUseSign)
	if err != nil {
		t.Fatal(err)
	}
	if kid != "registered" || public.KeyID != "registered" {
		t.Errorf("kid = %s, public kid = %s", kid, public.KeyID)
	}
}

// A published key states the algorithm it is for.
func TestPublishedKeysStateTheirAlgAndUse(t *testing.T) {
	path, _ := writeTestKeyPEM(t, elliptic.P256())
	for _, tc := range []struct {
		name    string
		use     keyUse
		wantUse string
		wantAlg string
	}{
		{"signing key", keyUseSign, "sig", "ES256"},
		{"encryption key", keyUseEncrypt, "enc", "ECDH-ES"},
		{"client key", keyUseClientAuth, "sig", "ES256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, public, _, err := loadKeyConfig(KeyConfig{KeyPEMPath: path}, "", tc.use)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(public)
			if err != nil {
				t.Fatal(err)
			}
			var published map[string]any
			if err := json.Unmarshal(data, &published); err != nil {
				t.Fatal(err)
			}
			if published["alg"] != tc.wantAlg || published["use"] != tc.wantUse {
				t.Errorf("published %s", data)
			}
			if _, private := published["d"]; private {
				t.Error("published the private part")
			}
		})
	}
}

func TestClientKeyPublishesTheAlgOfItsCurve(t *testing.T) {
	path, _ := writeTestKeyPEM(t, elliptic.P384())
	_, public, _, err := loadKeyConfig(KeyConfig{KeyPEMPath: path}, "", keyUseClientAuth)
	if err != nil {
		t.Fatal(err)
	}
	if public.Algorithm != "ES384" {
		t.Errorf("alg = %s", public.Algorithm)
	}
}

// gemSpec_IDP_FD A_23196: the entity statement is signed with a P-256 key only.
func TestA_23196_TheSigningKeyHasToBeP256(t *testing.T) {
	path, _ := writeTestKeyPEM(t, elliptic.P384())
	if _, _, _, err := loadKeyConfig(KeyConfig{KeyPEMPath: path}, "", keyUseSign); err == nil {
		t.Error("accepted a key that cannot sign ES256")
	}
}

func TestLoadKeyConfigRefusesKeysThatCannotDoTheJob(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPath := filepath.Join(t.TempDir(), "rsa.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	if err := os.WriteFile(rsaPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, use := range []keyUse{keyUseSign, keyUseEncrypt, keyUseClientAuth} {
		if _, _, _, err := loadKeyConfig(KeyConfig{KeyPEMPath: rsaPath}, "", use); err == nil {
			t.Errorf("use %d accepted an RSA key", use)
		}
	}
	publicJWK := map[string]any{"kty": "EC", "crv": "P-256", "x": "cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs", "y": "XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw"}
	if _, _, _, err := loadKeyConfig(KeyConfig{JWK: publicJWK}, "", keyUseSign); err == nil {
		t.Error("accepted a public key as the private key")
	}
}

func TestParsePrivateKeyPEMReadsTheFormatsOfTheStandardLibrary(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for blockType, der := range map[string][]byte{"EC PRIVATE KEY": sec1, "PRIVATE KEY": pkcs8} {
		parsed, err := parsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
		if err != nil {
			t.Fatalf("%s: %v", blockType, err)
		}
		if !key.Equal(parsed.Key.(*ecdsa.PrivateKey)) {
			t.Errorf("%s: another key", blockType)
		}
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})); err == nil {
		t.Error("accepted a public key")
	}
	if _, err := parsePrivateKeyPEM([]byte("no PEM here")); err == nil {
		t.Error("accepted garbage")
	}
}

func TestCertPEMPathPublishesTheCertificateAsX5c(t *testing.T) {
	keyPath, err := generateTempKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(keyPath)
	certPath, err := generateCert(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(certPath)

	_, public, _, err := loadKeyConfig(KeyConfig{KeyPEMPath: keyPath, CertPEMPath: certPath}, "", keyUseClientAuth)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	var published struct {
		X5c []string `json:"x5c"`
	}
	if err := json.Unmarshal(data, &published); err != nil {
		t.Fatal(err)
	}
	der, err := loadCertBytesFromPem(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(published.X5c) != 1 || published.X5c[0] != base64.StdEncoding.EncodeToString(der) {
		t.Errorf("x5c = %v", published.X5c)
	}
}

func TestJwkMarshalsBackToAPlainJWK(t *testing.T) {
	const input = `{"kty":"EC","crv":"P-256","x":"cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs","y":"XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw","kid":"k","use":"sig","alg":"ES256"}`
	var jwk Jwk
	if err := json.Unmarshal([]byte(input), &jwk); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(&jwk)
	if err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(input), &want); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Errorf("got %s", data)
	}
	for member, value := range want {
		if got[member] != value {
			t.Errorf("%s = %v, want %v", member, got[member], value)
		}
	}
}

func TestJwkAsSetWithoutAKeyFails(t *testing.T) {
	if _, err := new(Jwk).AsSet(); err == nil {
		t.Error("made a set of no key")
	}
}

func TestResolveTrustAnchorKnowsTheBuiltInMasters(t *testing.T) {
	for master := range knownFedMasters {
		keys, err := (&RelyingPartyConfig{FedMasterURL: master}).resolveTrustAnchor()
		if err != nil {
			t.Fatal(err)
		}
		if len(keys.Key("puk_fedmaster_sig")) != 1 || keys.Keys[0].Algorithm != "ES256" {
			t.Errorf("%s: %+v", master, keys.Keys)
		}
	}
	if _, err := (&RelyingPartyConfig{FedMasterURL: "https://unknown.example"}).resolveTrustAnchor(); err == nil {
		t.Error("made up a trust anchor for an unknown master")
	}
}

func TestServeSignedJwksVerifiesAndKeepsItsShape(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := jose.JSONWebKey{Key: key.Public(), KeyID: "enc", Use: "enc", Algorithm: "ECDH-ES"}
	rp := &RelyingParty{
		sigPrivateKey: key,
		signKid:       "sign-kid",
		entityStatement: &EntityStatement{
			Subject:  "https://rp.example",
			Metadata: &Metadata{OpenidRelyingParty: &OpenIDRelyingPartyMetadata{Jwks: &Jwks{Keys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{enc}}}}},
		},
	}
	recorder := httptest.NewRecorder()
	rp.ServeSignedJwks(recorder, httptest.NewRequest(http.MethodGet, "/jwks", nil))
	if got := recorder.Header().Get("Content-Type"); got != "application/jwk-set+jwt" {
		t.Errorf("content type = %s", got)
	}
	body := recorder.Body.Bytes()
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(strings.SplitN(string(body), ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		t.Fatal(err)
	}
	if header.Alg != "ES256" || header.Kid != "sign-kid" || header.Typ != "jwk-set+json" {
		t.Errorf("header = %+v", header)
	}
	var claims struct {
		Iss  string `json:"iss"`
		Iat  int64  `json:"iat"`
		Exp  int64  `json:"exp"`
		Keys struct {
			Keys []map[string]any `json:"keys"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(unverifiedPayload(t, body), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "https://rp.example" || claims.Iat == 0 || claims.Exp <= claims.Iat {
		t.Errorf("claims = %+v", claims)
	}
	if len(claims.Keys.Keys) != 1 || claims.Keys.Keys[0]["kid"] != "enc" {
		t.Errorf("keys = %+v", claims.Keys)
	}
}
