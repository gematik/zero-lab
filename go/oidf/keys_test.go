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
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
	"github.com/gematik/zero-lab/go/openid/providers"
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
			got, err := thumbprint(jwk.Key.Key)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("thumbprint = %s, want %s", got, tc.want)
			}
		})
	}
}

// testKeyFiles names key files, which the loaders of these tests never read.
func testKeyFiles() KeyFiles {
	return KeyFiles{
		SignKey:   KeyFile{KeyPEMPath: "sign.pem"},
		EncKey:    KeyFile{KeyPEMPath: "enc.pem"},
		ClientKey: KeyFile{KeyPEMPath: "client.pem", CertPEMPath: "client-cert.pem"},
	}
}

// buildKind runs Kind on file, with loader as the host's key loader, in a providers file in dir.
func buildKind(t *testing.T, stub *federationStub, file KeyFiles, dir string, loader func(KeyFiles) (Keys, error)) (*RelyingParty, error) {
	t.Helper()
	config := testRelyingPartyConfig(t, stub)
	decode := func(v any) error {
		target, ok := v.(*FileConfig)
		if !ok {
			return fmt.Errorf("decode into a %T", v)
		}
		*target = FileConfig{RelyingPartyConfig: *config, KeyFiles: file}
		return nil
	}
	var built *RelyingParty
	_, err := Kind("", NewMemoryDocuments(16, nil), loader, func(rp *RelyingParty) { built = rp })(decode, providers.Env{BaseDir: dir, HTTPClient: stub.Client()})
	return built, err
}

// withoutKIDs is keys as a host's loader returns them: the kids are Kind's to set.
func withoutKIDs(keys Keys) Keys {
	keys.SignKID, keys.DecryptKID, keys.ClientKID = "", "", ""
	return keys
}

func TestKindDefaultsTheKidToTheThumbprint(t *testing.T) {
	keys := newTestKeys(t)
	rp, err := buildKind(t, newFederationStub(t), testKeyFiles(), "", func(KeyFiles) (Keys, error) { return withoutKIDs(keys), nil })
	if err != nil {
		t.Fatal(err)
	}
	encryption, err := encryptionPublicKey(keys.Decrypt)
	if err != nil {
		t.Fatal(err)
	}
	published := publishedKeys(t, rp)
	for name, public := range map[string]crypto.PublicKey{"sign": keys.Sign.Public(), "enc": encryption, "client": keys.Client.Leaf.PublicKey} {
		sum, err := (&jose.JSONWebKey{Key: public}).Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if published[base64.RawURLEncoding.EncodeToString(sum)] == nil {
			t.Errorf("%s: not published under its thumbprint: %v", name, published)
		}
	}
}

func TestKindTakesTheConfiguredKid(t *testing.T) {
	files := testKeyFiles()
	files.SignKey.Kid, files.EncKey.Kid, files.ClientKey.Kid = "sign", "enc", "client"
	rp, err := buildKind(t, newFederationStub(t), files, "", func(KeyFiles) (Keys, error) { return newTestKeys(t), nil })
	if err != nil {
		t.Fatal(err)
	}
	published := publishedKeys(t, rp)
	for kid, want := range map[string][3]string{
		"sign":   {"statement", "sig", "ES256"},
		"enc":    {"openid_relying_party", "enc", "ECDH-ES"},
		"client": {"openid_relying_party", "sig", "ES256"},
	} {
		key := published[kid]
		if key == nil || key["in"] != want[0] || key["use"] != want[1] || key["alg"] != want[2] {
			t.Errorf("%s: %v", kid, key)
		}
	}
}

func TestKindResolvesRelativeKeyPathsAgainstTheFilesDirectory(t *testing.T) {
	files := testKeyFiles()
	files.EncKey.KeyPEMPath = "/etc/keys/enc.pem"
	var got KeyFiles
	_, err := buildKind(t, newFederationStub(t), files, "/srv/config", func(files KeyFiles) (Keys, error) {
		got = files
		return newTestKeys(t), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := KeyFiles{
		SignKey:   KeyFile{KeyPEMPath: "/srv/config/sign.pem"},
		EncKey:    KeyFile{KeyPEMPath: "/etc/keys/enc.pem"},
		ClientKey: KeyFile{KeyPEMPath: "/srv/config/client.pem", CertPEMPath: "/srv/config/client-cert.pem"},
	}
	if got != want {
		t.Errorf("the loader got %+v, want %+v", got, want)
	}
}

// Keys rule 1: oidf reads no key file, so a Kind without the host's loader has no keys and refuses to start.
func TestKeysRule1_KindWithoutAKeyLoaderIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	fetches := stub.countFetches()
	if _, err := buildKind(t, stub, testKeyFiles(), "", nil); err == nil || !strings.Contains(err.Error(), "loader") {
		t.Errorf("err = %v", err)
	}
	if n := fetches.count("/.well-known/openid-federation"); n != 0 {
		t.Errorf("%d fetches", n)
	}
}

// Servers rule 17: incomplete key files and a certificate named for the signing or the ID token key, which would be
// ignored, stop the start before a key is loaded.
func TestServerRule17_KeyFilesThatAreIncompleteOrMisplacedAreRefused(t *testing.T) {
	stub := newFederationStub(t)
	for name, c := range map[string]struct {
		change func(*KeyFiles)
		reason string
	}{
		"no signing key":              {func(f *KeyFiles) { f.SignKey.KeyPEMPath = "" }, "sign_key.key_pem_path is required"},
		"no ID token key":             {func(f *KeyFiles) { f.EncKey.KeyPEMPath = "" }, "enc_key.key_pem_path is required"},
		"no client key":               {func(f *KeyFiles) { f.ClientKey.KeyPEMPath = "" }, "client_key.key_pem_path is required"},
		"no client certificate":       {func(f *KeyFiles) { f.ClientKey.CertPEMPath = "" }, "client_key.cert_pem_path is required"},
		"a signing key certificate":   {func(f *KeyFiles) { f.SignKey.CertPEMPath = "cert.pem" }, "cert_pem_path belongs to client_key only"},
		"an ID token key certificate": {func(f *KeyFiles) { f.EncKey.CertPEMPath = "cert.pem" }, "cert_pem_path belongs to client_key only"},
	} {
		t.Run(name, func(t *testing.T) {
			files := testKeyFiles()
			c.change(&files)
			loaded := false
			_, err := buildKind(t, stub, files, "", func(KeyFiles) (Keys, error) {
				loaded = true
				return newTestKeys(t), nil
			})
			if err == nil || !strings.Contains(err.Error(), c.reason) {
				t.Errorf("err = %v", err)
			}
			if loaded {
				t.Error("the keys were loaded")
			}
		})
	}
}

func TestKindNamesTheLoadersError(t *testing.T) {
	failure := errors.New("enc_key: no such file")
	_, err := buildKind(t, newFederationStub(t), testKeyFiles(), "", func(KeyFiles) (Keys, error) { return Keys{}, failure })
	if !errors.Is(err, failure) {
		t.Errorf("err = %v", err)
	}
}

// gemSpec_IDP_FD A_23196: keys from a host's loader are held to P-256 like any others, before a kid is computed.
func TestA_23196_KindRefusesKeysThatAreNotP256(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stub := newFederationStub(t)
	for name, change := range map[string]func(*Keys){
		"signing key": func(k *Keys) { k.Sign = p384 },
		"client key":  func(k *Keys) { k.Client = selfSignedCertificate(t, p384) },
	} {
		keys := withoutKIDs(newTestKeys(t))
		change(&keys)
		if _, err := buildKind(t, stub, testKeyFiles(), "", func(KeyFiles) (Keys, error) { return keys, nil }); !errors.Is(err, ErrKeys) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// gemSpec_IDP_FD A_23196: New takes P-256 keys only, so an RSA key a host hands in stops the start.
func TestA_23196_NewRefusesRSAKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	stub := newFederationStub(t)
	for name, change := range map[string]func(*Keys){
		"signing key": func(k *Keys) { k.Sign = rsaKey },
		"client key":  func(k *Keys) { k.Client.PrivateKey = rsaKey },
	} {
		keys := newTestKeys(t)
		change(&keys)
		if _, err := New(t.Context(), testRelyingPartyConfig(t, stub), keys); !errors.Is(err, ErrKeys) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// publishedKeys reads the keys of the relying party's signed statement by kid: its own jwks and those of
// openid_relying_party.
func publishedKeys(t *testing.T, rp *RelyingParty) map[string]map[string]any {
	t.Helper()
	signed, err := rp.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Jwks struct {
			Keys []map[string]any `json:"keys"`
		} `json:"jwks"`
		Metadata struct {
			OpenidRelyingParty struct {
				Jwks struct {
					Keys []map[string]any `json:"keys"`
				} `json:"jwks"`
			} `json:"openid_relying_party"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(unverifiedPayload(t, signed), &claims); err != nil {
		t.Fatal(err)
	}
	published := map[string]map[string]any{}
	for _, key := range claims.Jwks.Keys {
		key["in"] = "statement"
		published[key["kid"].(string)] = key
	}
	for _, key := range claims.Metadata.OpenidRelyingParty.Jwks.Keys {
		key["in"] = "openid_relying_party"
		published[key["kid"].(string)] = key
	}
	return published
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
	rp := newTestRelyingParty(t, nil)
	recorder := httptest.NewRecorder()
	rp.ServeSignedJwks(recorder, httptest.NewRequest(http.MethodGet, "/jwks", nil))
	if got := recorder.Header().Get("Content-Type"); got != "application/jwk-set+jwt" {
		t.Errorf("content type = %s", got)
	}
	body := recorder.Body.Bytes()
	if _, err := openid.VerifyJWS(body, rp.entityStatement.Jwks.Keys, trustAnchorKeys); err != nil {
		t.Fatal(err)
	}
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
	if header.Alg != "ES256" || header.Kid != "sign-kid" || header.Typ != "jwk-set+jwt" {
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
	if len(claims.Keys.Keys) != 2 || claims.Keys.Keys[0]["kid"] != "enc-kid" || claims.Keys.Keys[1]["kid"] != "client-kid" {
		t.Errorf("keys = %+v", claims.Keys)
	}
}

// gemSpec_IDP_FD A_23196 allows a relying party EC keys on P-256 only, and keys rule 1 publishes no private key part:
// a signed JWKS that would hold another key is not signed.
func TestA_23196_ASignedJWKSWithAKeyOtherThanAPublicP256KeyIsRefused(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private := newTestKey(t)
	for name, c := range map[string]struct {
		key  jose.JSONWebKey
		want string
	}{
		"RSA":     {jose.JSONWebKey{Key: rsaKey.Public(), KeyID: "rsa"}, "no P-256 key"},
		"P-384":   {jose.JSONWebKey{Key: p384.Public(), KeyID: "p384"}, "no P-256 key"},
		"private": {jose.JSONWebKey{Key: private, KeyID: "private"}, "private key"},
	} {
		rp := literalRelyingParty(t, newTestKey(t))
		rp.relyingPartyKeys.Keys = append(rp.relyingPartyKeys.Keys, c.key)
		if _, err := rp.signJwks(time.Now()); !errors.Is(err, ErrEntityStatement) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A signed JWKS too large for a member to take is not signed. Internal invariant of signing, servers.md rule 2.
func TestServerRule2_ASignedJWKSLargerThanItsBoundIsRefused(t *testing.T) {
	rp := literalRelyingParty(t, newTestKey(t))
	public := rp.relyingPartyKeys.Keys[0]
	// A public P-256 JWK takes more than 100 bytes.
	for len(rp.relyingPartyKeys.Keys)*100 <= maxStatementBytes {
		rp.relyingPartyKeys.Keys = append(rp.relyingPartyKeys.Keys, public)
	}
	if _, err := rp.signJwks(time.Now()); !errors.Is(err, ErrEntityStatement) || !strings.Contains(err.Error(), "more than") {
		t.Errorf("err = %v", err)
	}
	rp.relyingPartyKeys.Keys = rp.relyingPartyKeys.Keys[:1]
	if _, err := rp.signJwks(time.Now()); err != nil {
		t.Errorf("one key: %v", err)
	}
}
