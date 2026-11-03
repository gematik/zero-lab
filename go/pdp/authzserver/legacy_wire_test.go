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

package authzserver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
)

// testdata/legacy_issued.json was made by the code of commit a11372a, the last one built on the previous JOSE
// library, from its issuing paths: the server's published key sets and tokens, and its generated keys.
type legacyIssued struct {
	SigningJWK        json.RawMessage `json:"signing_jwk"`
	KeyID             string          `json:"kid"`
	JWKS              json.RawMessage `json:"jwks"`
	JWKSThumbprintKid json.RawMessage `json:"jwks_thumbprint_kid"`
	TokenDPoP         string          `json:"access_token_dpop"`
	TokenBearer       string          `json:"access_token_bearer"`
	TokenEmptyAud     string          `json:"access_token_empty_aud"`
	GeneratedJWK      json.RawMessage `json:"generated_jwk"`
	GeneratedPublic   json.RawMessage `json:"generated_public_jwk"`
	GeneratedSet      json.RawMessage `json:"generated_set"`
	GeneratedPubSet   json.RawMessage `json:"generated_public_set"`
}

func readLegacyIssued(t *testing.T) legacyIssued {
	t.Helper()
	raw, err := os.ReadFile("testdata/legacy_issued.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture legacyIssued
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func legacySigner(t *testing.T, fixture legacyIssued) crypto.Signer {
	t.Helper()
	key, err := openid.ParseKey(fixture.SigningJWK)
	if err != nil {
		t.Fatal(err)
	}
	return key.Key.(*ecdsa.PrivateKey)
}

func assertSameJSON(t *testing.T, got []byte, want []byte) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("got: %v", err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("want: %v", err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestLegacyWire_PublishedJWKSIsUnchanged(t *testing.T) {
	fixture := readLegacyIssued(t)
	signer := legacySigner(t, fixture)
	for name, c := range map[string]struct {
		kid  string
		want []byte
	}{
		"configured kid": {fixture.KeyID, fixture.JWKS},
		"thumbprint kid": {"", fixture.JWKSThumbprintKid},
	} {
		t.Run(name, func(t *testing.T) {
			server, err := New(Config{Issuer: testIssuer, SigningKey: &SigningKey{Signer: signer, KeyID: c.kid}})
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			if err := server.JWKS(rec, httptest.NewRequest(http.MethodGet, "/jwks", nil)); err != nil {
				t.Fatal(err)
			}
			assertSameJSON(t, rec.Body.Bytes(), c.want)
		})
	}
}

func TestLegacyWire_TokensOfTheOldServerStillVerify(t *testing.T) {
	fixture := readLegacyIssued(t)
	server, err := New(Config{Issuer: testIssuer, SigningKey: &SigningKey{Signer: legacySigner(t, fixture), KeyID: fixture.KeyID}})
	if err != nil {
		t.Fatal(err)
	}
	for jti, token := range map[string]string{
		"legacy-session":   fixture.TokenDPoP,
		"legacy-bearer":    fixture.TokenBearer,
		"legacy-empty-aud": fixture.TokenEmptyAud,
	} {
		t.Run(jti, func(t *testing.T) {
			claims, err := server.verifyOwnToken(token, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if claims.JTI != jti || claims.Exp == 0 || claims.Iat == 0 {
				t.Fatalf("claims = %+v", claims)
			}
		})
	}
}

func decodeSegment(t *testing.T, segment string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]any
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	return members
}

// Apart from the instants, a token issued now reads as the old server's did, header and claims.
func TestLegacyWire_IssuedTokensKeepTheirShape(t *testing.T) {
	fixture := readLegacyIssued(t)
	server, err := New(Config{Issuer: testIssuer, SigningKey: &SigningKey{Signer: legacySigner(t, fixture), KeyID: fixture.KeyID}})
	if err != nil {
		t.Fatal(err)
	}
	const century = 100 * 365 * 24 * time.Hour
	for name, c := range map[string]struct {
		session *Session
		old     string
	}{
		"bound to a key": {&Session{ID: "legacy-session", ClientID: testClientID, Audience: []string{"https://rs.example"}, Scopes: []string{"a", "b"}, DPoPThumbprint: "legacy-jkt", AccessTokenDuration: century, ExpiresAt: time.Now().Add(century)}, fixture.TokenDPoP},
		"bearer":         {&Session{ID: "legacy-bearer", ClientID: testClientID, AccessTokenDuration: century, ExpiresAt: time.Now().Add(century)}, fixture.TokenBearer},
		"empty audience": {&Session{ID: "legacy-empty-aud", ClientID: testClientID, Audience: []string{}, Scopes: []string{"a"}, AccessTokenDuration: century, ExpiresAt: time.Now().Add(century)}, fixture.TokenEmptyAud},
	} {
		t.Run(name, func(t *testing.T) {
			issued, err := server.issueOrRefreshTokens(c.session)
			if err != nil {
				t.Fatal(err)
			}
			newParts, oldParts := strings.Split(issued.AccessToken, "."), strings.Split(c.old, ".")
			if newParts[0] != oldParts[0] {
				t.Fatalf("header = %q, want %q", newParts[0], oldParts[0])
			}
			newClaims, oldClaims := decodeSegment(t, newParts[1]), decodeSegment(t, oldParts[1])
			for _, instant := range []string{"iat", "exp"} {
				if _, ok := newClaims[instant].(float64); !ok {
					t.Fatalf("%s = %v", instant, newClaims[instant])
				}
				delete(newClaims, instant)
				delete(oldClaims, instant)
			}
			if !reflect.DeepEqual(newClaims, oldClaims) {
				t.Fatalf("claims = %v, want %v", newClaims, oldClaims)
			}
		})
	}
}

func TestLegacyWire_GeneratedKeysKeepTheirFormAndThumbprints(t *testing.T) {
	fixture := readLegacyIssued(t)
	key, err := openid.ParseKey(fixture.GeneratedJWK)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := ThumbprintS256(key)
	if err != nil {
		t.Fatal(err)
	}
	if thumbprint != key.KeyID {
		t.Fatalf("thumbprint %q differs from the old code's %q", thumbprint, key.KeyID)
	}
	public, err := PublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, got, fixture.GeneratedPublic)

	set, err := openid.ParseKeySet(fixture.GeneratedSet)
	if err != nil {
		t.Fatal(err)
	}
	publicSet, err := PublicJwkSet(set)
	if err != nil {
		t.Fatal(err)
	}
	if got, err = json.Marshal(publicSet); err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, got, fixture.GeneratedPubSet)

	generated, err := GenerateRandomJwk()
	if err != nil {
		t.Fatal(err)
	}
	if got, err = json.Marshal(generated); err != nil {
		t.Fatal(err)
	}
	var newMembers, oldMembers map[string]any
	if err := json.Unmarshal(got, &newMembers); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixture.GeneratedJWK, &oldMembers); err != nil {
		t.Fatal(err)
	}
	for member := range oldMembers {
		if _, ok := newMembers[member]; !ok {
			t.Fatalf("generated JWK %s lacks %q", got, member)
		}
	}
	if len(newMembers) != len(oldMembers) {
		t.Fatalf("generated JWK %s has other members than %v", got, oldMembers)
	}
}

// RFC 7638 Section 3.1 gives this key and its SHA-256 thumbprint.
func TestRFC7638_ThumbprintMatchesTheTestVector(t *testing.T) {
	key, err := openid.ParseKey([]byte(`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := key.Key.(*rsa.PublicKey); !ok {
		t.Fatalf("key = %T", key.Key)
	}
	got, err := ThumbprintS256(key)
	if err != nil {
		t.Fatal(err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Fatalf("thumbprint = %q, want %q", got, want)
	}
}

func TestPublicKeyOfASymmetricKeyIsRefused(t *testing.T) {
	if _, err := PublicKey(&jose.JSONWebKey{Key: []byte("secret")}); err == nil {
		t.Fatal("a symmetric key was published")
	}
}

type derSigner struct {
	crypto.Signer
	der []byte
}

func (s derSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return s.der, nil }

// RFC 7518 Section 3.4: R and S are fixed-length, whatever the signer's DER holds.
func TestRFC7518_3_4_SignatureIsConvertedToFixedLength(t *testing.T) {
	der, err := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), big.NewInt(2)})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := es256OpaqueSigner{signer: derSigner{der: der}}.SignPayload([]byte("input"), jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 64)
	want[31], want[63] = 1, 2
	if !bytes.Equal(signature, want) {
		t.Fatalf("signature = %x", signature)
	}
}

func TestSignerOutputThatIsNotAnES256SignatureIsRefused(t *testing.T) {
	tooLong, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	negative, err := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(-1), big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{"not DER": []byte("xx"), "too long": tooLong, "negative": negative, "trailing": append(append([]byte{}, negative...), 0)} {
		t.Run(name, func(t *testing.T) {
			if _, err := (es256OpaqueSigner{signer: derSigner{der: der}}).SignPayload([]byte("input"), jose.ES256); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := (es256OpaqueSigner{signer: newP256(t)}).SignPayload([]byte("input"), jose.ES384); err == nil {
		t.Fatal("signed with an algorithm other than ES256")
	}
}

// One signer serves all requests of the server.
func TestSigningKey_tokens_can_be_signed_concurrently(t *testing.T) {
	server, _ := newTestServer(t)
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			raw, err := server.signAccessToken(map[string]any{"sub": "s"})
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := openid.VerifyJWS(raw, server.jwks, openid.VerifyOptions{RequireKeyAlgorithm: true}); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
}

func hs256(t *testing.T, header, payload string, secret []byte) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func unsecured(header, payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "."
}

// What introspection was checking through pep: the published key by kid, and exp, nbf and iat with a minute of skew.
func TestIntrospection_OnlyAVerifiedLiveTokenOfThisServerIsActive(t *testing.T) {
	server, _ := newTestServer(t)
	now := time.Unix(1_800_000_000, 0)
	pastSkew := now.Add(-ownTokenSkew).Unix()
	insideSkew := now.Add(-ownTokenSkew + time.Second).Unix()
	futureSkew := now.Add(ownTokenSkew + time.Second).Unix()
	sign := func(claims map[string]any) string {
		t.Helper()
		raw, err := server.signAccessToken(claims)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	stranger := &jose.JSONWebKey{Key: newP256(t), KeyID: server.signerKeyID}
	public, err := json.Marshal(server.jwks.Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	withoutKid := signES256(t, &jose.JSONWebKey{Key: newP256(t)}, map[string]any{"jti": "a", "exp": futureSkew})

	for name, c := range map[string]struct {
		token  string
		active bool
	}{
		"live":                        {sign(map[string]any{"jti": "a", "exp": futureSkew}), true},
		"no exp":                      {sign(map[string]any{"jti": "a"}), true},
		"expired inside the skew":     {sign(map[string]any{"jti": "a", "exp": insideSkew}), true},
		"expired past the skew":       {sign(map[string]any{"jti": "a", "exp": pastSkew}), false},
		"nbf past the skew":           {sign(map[string]any{"jti": "a", "nbf": futureSkew}), false},
		"iat past the skew":           {sign(map[string]any{"jti": "a", "iat": futureSkew}), false},
		"exp is a string":             {sign(map[string]any{"jti": "a", "exp": "4102444800"}), false},
		"another key, same kid":       {signES256(t, stranger, map[string]any{"jti": "a", "exp": futureSkew}), false},
		"no kid":                      {withoutKid, false},
		"alg none":                    {unsecured(`{"alg":"none","kid":"`+server.signerKeyID+`"}`, `{"jti":"a"}`), false},
		"HS256, public key as secret": {hs256(t, `{"alg":"HS256","kid":"`+server.signerKeyID+`"}`, `{"jti":"a"}`, public), false},
		"not a JWT":                   {"not-a-jwt", false},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := server.verifyOwnToken(c.token, now); (err == nil) != c.active {
				t.Fatalf("err = %v, want active %v", err, c.active)
			}
		})
	}
}

func TestIntrospection_EndpointAnswersWithTheTokensInstants(t *testing.T) {
	server, signKey := newTestServer(t)
	resp := httptest.NewRecorder()
	if err := server.TokenEndpoint(resp, clientCredentialsRequest(t, signClientAssertion(t, server, signKey, nil))); err != nil {
		t.Fatalf("token: %v", err)
	}
	var tr TokenResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &tr); err != nil {
		t.Fatal(err)
	}
	introspect := func(token string) IntrospectionResponse {
		t.Helper()
		form := url.Values{}
		form.Set("client_assertion_type", ClientAssertionTypeJWTBearer)
		form.Set("client_assertion", signClientAssertion(t, server, signKey, nil))
		form.Set("token", token)
		req := httptest.NewRequest(http.MethodPost, testIssuer+"/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		if err := server.IntrospectionEndpoint(rec, req); err != nil {
			t.Fatalf("introspect: %v", err)
		}
		var ir IntrospectionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &ir); err != nil {
			t.Fatal(err)
		}
		return ir
	}
	ir := introspect(tr.AccessToken)
	if !ir.Active || ir.Exp == 0 || ir.Iat == 0 || ir.ClientID != testClientID {
		t.Fatalf("response = %+v", ir)
	}
	if ir.Cnf["jkt"] != testDPoPKey.Thumbprint() {
		t.Fatalf("cnf = %v", ir.Cnf)
	}
	if ir := introspect("not-a-jwt"); ir.Active {
		t.Fatalf("response = %+v", ir)
	}
}

// RFC 7523 Section 3: the assertion is checked against the one key registered for its client. It never went through
// a key set, and a client's assertion does not have to name its key, so a missing or other kid stays acceptable;
// everything else about the signature does not.
func TestClientAssertion_IsVerifiedOnlyWithTheRegisteredKeyAndES256(t *testing.T) {
	server, signKey := newTestServer(t)
	now := time.Now()
	good := map[string]any{"aud": []string{testIssuer}, "exp": now.Add(time.Minute).Unix()}
	client, err := server.clientsRegistry.GetClient(testClientID)
	if err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(client.Key())
	if err != nil {
		t.Fatal(err)
	}
	withKid := func(kid string) *jose.JSONWebKey { return &jose.JSONWebKey{Key: signKey.Key, KeyID: kid} }
	goodJSON, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		assertion string
		accepted  bool
	}{
		"no kid":                      {signES256(t, withKid(""), good), true},
		"another kid":                 {signES256(t, withKid("other"), good), true},
		"registered kid":              {signES256(t, signKey, good), true},
		"another key":                 {signES256(t, &jose.JSONWebKey{Key: newP256(t), KeyID: signKey.KeyID}, good), false},
		"alg none":                    {unsecured(`{"alg":"none"}`, string(goodJSON)), false},
		"no alg":                      {signWithHeader(t, signKey.Key.(*ecdsa.PrivateKey), `{"kid":"`+signKey.KeyID+`"}`, string(goodJSON)), false},
		"HS256, public key as secret": {hs256(t, `{"alg":"HS256"}`, string(goodJSON), public), false},
		"nested JWS as payload":       {signES256Raw(t, signKey, []byte(signES256(t, signKey, good))), false},
		"audience elsewhere":          {signES256(t, signKey, map[string]any{"aud": []string{"https://evil.example"}, "exp": now.Add(time.Minute).Unix()}), false},
		"no audience":                 {signES256(t, signKey, map[string]any{"exp": now.Add(time.Minute).Unix()}), false},
		"expired inside the skew":     {signES256(t, signKey, map[string]any{"aud": []string{testIssuer}, "exp": now.Add(-clientAssertionSkew + 5*time.Second).Unix()}), true},
		"expired past the skew":       {signES256(t, signKey, map[string]any{"aud": []string{testIssuer}, "exp": now.Add(-clientAssertionSkew - time.Second).Unix()}), false},
		"nbf past the skew":           {signES256(t, signKey, map[string]any{"aud": []string{testIssuer}, "nbf": now.Add(clientAssertionSkew + 5*time.Second).Unix()}), false},
		"iat past the skew":           {signES256(t, signKey, map[string]any{"aud": []string{testIssuer}, "iat": now.Add(clientAssertionSkew + 5*time.Second).Unix()}), false},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyClientAssertion(c.assertion, client.Key(), testIssuer, now); (err == nil) != c.accepted {
				t.Fatalf("err = %v, want accepted %v", err, c.accepted)
			}
		})
	}
}

// signWithHeader makes a valid ES256 signature under a header the library would not produce.
func signWithHeader(t *testing.T, key *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signES256Raw(t *testing.T, key *jose.JSONWebKey, payload []byte) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestClientAssertion_ForeignKeyTypeIsRefused(t *testing.T) {
	_, signKey := newTestServer(t)
	assertion := signES256(t, signKey, map[string]any{"aud": []string{testIssuer}})
	for name, key := range map[string]*jose.JSONWebKey{
		"symmetric": {Key: []byte("secret")},
		"RSA":       {Key: mustRSAPublic(t)},
	} {
		t.Run(name, func(t *testing.T) {
			err := verifyClientAssertion(assertion, key, testIssuer, time.Now())
			if err == nil || errors.Is(err, openid.ErrAudienceMismatch) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func mustRSAPublic(t *testing.T) *rsa.PublicKey {
	t.Helper()
	key, err := openid.ParseKey([]byte(`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`))
	if err != nil {
		t.Fatal(err)
	}
	return key.Key.(*rsa.PublicKey)
}

// A hostile assertion must only ever be refused, never crash the endpoint.
func FuzzVerifyClientAssertion(f *testing.F) {
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJFUzI1NiJ9.e30.AA")
	f.Add(unsecured(`{"alg":"none"}`, `{"aud":["x"]}`))
	public := jose.JSONWebKey{Key: &ecdsaTestKey.PublicKey}
	f.Fuzz(func(_ *testing.T, assertion string) {
		_ = verifyClientAssertion(assertion, &public, testIssuer, time.Now())
		_, _ = parseClientAssertionClaims(assertion)
	})
}

var ecdsaTestKey = func() *ecdsa.PrivateKey {
	key, err := openid.ParseKey([]byte(`{"crv":"P-256","d":"wCAQdVx6LR3BRFACmporyQ2tMGu755WNJsfhu5sx3Qk","kty":"EC","x":"CSe6WWOsFaUSjp437htjVBkDdF5LRj_ZvBfxQ4BecH4","y":"rhz8yAOajNwAH3DTujwepcsUQI-cBeSMGyCuByhbh-4"}`))
	if err != nil {
		panic(err)
	}
	return key.Key.(*ecdsa.PrivateKey)
}()
