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

package openid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func newECKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// signToken signs payload with a go-jose signer; kid, when set, goes into the protected header.
func signToken(t testing.TB, alg jose.SignatureAlgorithm, key any, kid string, payload []byte) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// signRawES256 builds a token by hand, for headers a conforming signer would not produce.
func signRawES256(t testing.TB, key *ecdsa.PrivateKey, header map[string]string, payload []byte) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func setOf(keys ...jose.JSONWebKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: keys}
}

var testPayload = []byte(`{"sub":"alice"}`)

func TestVerifyJWSReturnsPayloadOfTokenSignedByKeyOfKid(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	other := newECKey(t, elliptic.P256())
	keys := setOf(
		jose.JSONWebKey{Key: other.Public(), KeyID: "other"},
		jose.JSONWebKey{Key: key.Public(), KeyID: "k"},
	)
	payload, err := VerifyJWS([]byte(signToken(t, jose.ES256, key, "k", testPayload)), keys, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(testPayload) {
		t.Errorf("payload = %s", payload)
	}
}

func TestVerifyJWSAcceptsEveryAllowedAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, p384, p521 := newECKey(t, elliptic.P256()), newECKey(t, elliptic.P384()), newECKey(t, elliptic.P521())
	for _, tc := range []struct {
		alg     jose.SignatureAlgorithm
		private any
		public  any
	}{
		{jose.ES256, p256, p256.Public()},
		{jose.ES384, p384, p384.Public()},
		{jose.ES512, p521, p521.Public()},
		{jose.RS256, rsaKey, rsaKey.Public()},
		{jose.RS384, rsaKey, rsaKey.Public()},
		{jose.RS512, rsaKey, rsaKey.Public()},
		{jose.PS256, rsaKey, rsaKey.Public()},
		{jose.PS384, rsaKey, rsaKey.Public()},
		{jose.PS512, rsaKey, rsaKey.Public()},
		{jose.EdDSA, edPrivate, edPublic},
	} {
		t.Run(string(tc.alg), func(t *testing.T) {
			keys := setOf(jose.JSONWebKey{Key: tc.public, KeyID: "k"})
			if _, err := VerifyJWS([]byte(signToken(t, tc.alg, tc.private, "k", testPayload)), keys, VerifyOptions{}); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestRFC8725_3_2_VerifyJWSRefusesAlgNone(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	keys := setOf(jose.JSONWebKey{Key: key.Public(), KeyID: "k"})
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k"}`))
	body := base64.RawURLEncoding.EncodeToString(testPayload)
	for _, token := range []string{header + "." + body + ".", header + "." + body} {
		if _, err := VerifyJWS([]byte(token), keys, VerifyOptions{}); err == nil {
			t.Errorf("accepted %q", token)
		}
	}
}

// The classic confusion: an HS256 token keyed with the bytes of the public key an RS256 verifier would use.
func TestRFC8725_3_1_VerifyJWSRefusesHS256KeyedWithThePublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"k"}`))
	input := header + "." + base64.RawURLEncoding.EncodeToString(testPayload)
	mac := hmac.New(sha256.New, publicDER)
	mac.Write([]byte(input))
	token := input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	keys := setOf(jose.JSONWebKey{Key: rsaKey.Public(), KeyID: "k"})
	if _, err := VerifyJWS([]byte(token), keys, VerifyOptions{}); err == nil {
		t.Error("accepted an HS256 token against an RSA key")
	}
}

// Only the verifier's allowlist of algorithms is used, whatever keys the set holds.
func TestRFC8725_3_1_VerifyJWSRefusesHS256EvenWithASymmetricKeyInTheSet(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	keys := setOf(jose.JSONWebKey{Key: secret, KeyID: "k", Algorithm: "HS256"})
	if _, err := VerifyJWS([]byte(signToken(t, jose.HS256, secret, "k", testPayload)), keys, VerifyOptions{}); err == nil {
		t.Error("accepted HS256")
	}
}

func TestRFC7515_4_1_1_VerifyJWSRefusesTokenWithoutAlg(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	for name, jwk := range map[string]jose.JSONWebKey{
		"key states alg":    {Key: key.Public(), KeyID: "k", Algorithm: "ES256"},
		"key states no alg": {Key: key.Public(), KeyID: "k"},
	} {
		t.Run(name, func(t *testing.T) {
			token := signRawES256(t, key, map[string]string{"kid": "k"}, testPayload)
			if _, err := VerifyJWS([]byte(token), setOf(jwk), VerifyOptions{}); err == nil {
				t.Error("accepted a token without alg")
			}
		})
	}
}

func TestRFC7517_4_4_VerifyJWSRefusesAlgOtherThanTheKeyStates(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	keys := setOf(jose.JSONWebKey{Key: key.Public(), KeyID: "k", Algorithm: "ES384"})
	if _, err := VerifyJWS([]byte(signToken(t, jose.ES256, key, "k", testPayload)), keys, VerifyOptions{}); err == nil {
		t.Error("accepted ES256 against a key stating ES384")
	}
}

// ES256 is ECDSA on P-256 only.
func TestRFC7518_3_4_VerifyJWSRefusesCurveOtherThanTheAlgorithmNames(t *testing.T) {
	p384 := newECKey(t, elliptic.P384())
	keys := setOf(jose.JSONWebKey{Key: p384.Public(), KeyID: "k"})
	token := signRawES256(t, newECKey(t, elliptic.P256()), map[string]string{"alg": "ES256", "kid": "k"}, testPayload)
	if _, err := VerifyJWS([]byte(token), keys, VerifyOptions{}); err == nil {
		t.Error("accepted ES256 against a P-384 key")
	}
}

func TestRFC7517_4_2_VerifyJWSRefusesKeyMarkedForEncryption(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	keys := setOf(jose.JSONWebKey{Key: key.Public(), KeyID: "k", Use: "enc"})
	if _, err := VerifyJWS([]byte(signToken(t, jose.ES256, key, "k", testPayload)), keys, VerifyOptions{}); err == nil {
		t.Error("accepted a signature by an encryption key")
	}
}

func TestVerifyJWSRefusesPrivateKeyInTheSet(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	keys := setOf(jose.JSONWebKey{Key: key, KeyID: "k"})
	if _, err := VerifyJWS([]byte(signToken(t, jose.ES256, key, "k", testPayload)), keys, VerifyOptions{}); err == nil {
		t.Error("verified with a private key")
	}
}

func TestVerifyJWSRefusesUnknownKid(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	keys := setOf(jose.JSONWebKey{Key: key.Public(), KeyID: "k"})
	if _, err := VerifyJWS([]byte(signToken(t, jose.ES256, key, "unknown", testPayload)), keys, VerifyOptions{}); err == nil {
		t.Error("accepted a token whose kid is not in the set")
	}
}

func TestVerifyJWSWithKidUsesOnlyTheFirstKeyOfThatKid(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	keys := setOf(
		jose.JSONWebKey{Key: newECKey(t, elliptic.P256()).Public(), KeyID: "k"},
		jose.JSONWebKey{Key: key.Public(), KeyID: "k"},
	)
	if _, err := VerifyJWS([]byte(signToken(t, jose.ES256, key, "k", testPayload)), keys, VerifyOptions{}); err == nil {
		t.Error("tried the second key of a duplicate kid")
	}
}

func TestRFC7515_5_2_VerifyJWSRefusesTamperedPayload(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	keys := setOf(jose.JSONWebKey{Key: key.Public(), KeyID: "k"})
	parts := strings.Split(signToken(t, jose.ES256, key, "k", testPayload), ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"mallory"}`))
	if _, err := VerifyJWS([]byte(strings.Join(parts, ".")), keys, VerifyOptions{}); err == nil {
		t.Error("accepted a tampered payload")
	}
}

// The origin of a verification key has to be authenticated, which a key the token brings along is not.
func TestRFC7515_10_3_VerifyJWSIgnoresKeyEmbeddedInTheHeader(t *testing.T) {
	attacker := newECKey(t, elliptic.P256())
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: attacker},
		(&jose.SignerOptions{EmbedJWK: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(testPayload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	keys := setOf(jose.JSONWebKey{Key: newECKey(t, elliptic.P256()).Public()})
	if _, err := VerifyJWS([]byte(token), keys, VerifyOptions{}); err == nil {
		t.Error("trusted a key the token brought along")
	}
}

func TestVerifyJWSRefusesATokenWithoutKid(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	token := []byte(signToken(t, jose.ES256, key, "", testPayload))
	keys := setOf(jose.JSONWebKey{Key: key.Public(), KeyID: "k"})
	if _, err := VerifyJWS(token, keys, VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "no kid") {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyJWSWithRequireKeyAlgorithmRefusesKeyWithoutAlg(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	require := VerifyOptions{RequireKeyAlgorithm: true}
	token := []byte(signToken(t, jose.ES256, key, "k", testPayload))

	if _, err := VerifyJWS(token, setOf(jose.JSONWebKey{Key: key.Public(), KeyID: "k"}), require); err == nil {
		t.Error("used a key without alg")
	}
	if _, err := VerifyJWS(token, setOf(jose.JSONWebKey{Key: key.Public(), KeyID: "k", Algorithm: "ES256"}), require); err != nil {
		t.Error(err)
	}
}

func TestVerifyJWSWithoutRequireKeyAlgorithmAcceptsKeyWithoutAlg(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	token := []byte(signToken(t, jose.ES256, key, "k", testPayload))
	if _, err := VerifyJWS(token, setOf(jose.JSONWebKey{Key: key.Public(), KeyID: "k"}), VerifyOptions{}); err != nil {
		t.Error(err)
	}
}

// A JWT is always in the JWS or JWE Compact Serialization.
func TestRFC7519_1_VerifyJWSRefusesJSONSerialization(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(testPayload)
	if err != nil {
		t.Fatal(err)
	}
	keys := setOf(jose.JSONWebKey{Key: key.Public()})
	if _, err := VerifyJWS([]byte(signed.FullSerialize()), keys, VerifyOptions{}); err == nil {
		t.Error("accepted a JSON serialization")
	}
}

func TestVerifyJWSWithoutKeySetRefuses(t *testing.T) {
	key := newECKey(t, elliptic.P256())
	if _, err := VerifyJWS([]byte(signToken(t, jose.ES256, key, "", testPayload)), nil, VerifyOptions{}); err == nil {
		t.Error("verified without keys")
	}
}

const (
	p256JWK = `{"kty":"EC","crv":"P-256","x":"cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs","y":"XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw","kid":"p","use":"sig","alg":"ES256"}`
	// x25519JWK is a key the parser knows no type for, as a provider may publish beside its signing keys.
	x25519JWK = `{"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo","kid":"x"}`
	// offCurveJWK has its y equal to its x, which is not a point of P-256.
	offCurveJWK = `{"kty":"EC","crv":"P-256","x":"cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs","y":"cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs","kid":"c"}`
)

func TestRFC7517_5_ParseKeySetLeavesOutEntriesItCannotUse(t *testing.T) {
	keys, err := ParseKeySet([]byte(`{"keys":[` + x25519JWK + `,` + p256JWK + `,` + offCurveJWK + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "p" {
		t.Errorf("keys = %+v", keys.Keys)
	}
}

func TestParseKeySetFailsWhenNoEntryIsUsable(t *testing.T) {
	if _, err := ParseKeySet([]byte(`{"keys":[` + x25519JWK + `,` + offCurveJWK + `]}`)); err == nil {
		t.Error("accepted a set without a usable key")
	}
}

func TestParseKeySetTakesABareJWKAsASetOfOne(t *testing.T) {
	keys, err := ParseKeySet([]byte(p256JWK))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 1 {
		t.Errorf("%d keys", len(keys.Keys))
	}
}

func TestParseKeySetAcceptsAnEmptySet(t *testing.T) {
	keys, err := ParseKeySet([]byte(`{"keys":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if keys.Keys == nil {
		t.Error("an empty set has to marshal to an empty array, not null")
	}
}

func TestParseKeySetRefusesWhatIsNotAKeySet(t *testing.T) {
	for _, input := range []string{``, `null`, `[]`, `{"foo":1}`, `{"keys":null}`, `{"keys":{"keys":[]}}`} {
		if _, err := ParseKeySet([]byte(input)); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestParseKeySetRefusesMoreKeysThanTheBound(t *testing.T) {
	entries := make([]json.RawMessage, maxKeysInSet+1)
	for i := range entries {
		entries[i] = json.RawMessage(p256JWK)
	}
	data, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKeySet(data); err == nil {
		t.Error("accepted too many keys")
	}
}

func TestRFC7518_3_3_ParseKeyRefusesRSAKeyBelow2048Bits(t *testing.T) {
	modulus := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2047), big.NewInt(1))
	data, err := json.Marshal(jose.JSONWebKey{Key: &rsa.PublicKey{N: modulus, E: 65537}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKey(data); err != nil {
		t.Errorf("refused 2048 bits: %v", err)
	}
	modulus = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2046), big.NewInt(1))
	data, err = json.Marshal(jose.JSONWebKey{Key: &rsa.PublicKey{N: modulus, E: 65537}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKey(data); err == nil {
		t.Error("accepted 2047 bits")
	}
}
