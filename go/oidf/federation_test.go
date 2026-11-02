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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signJWS(t *testing.T, key *ecdsa.PrivateKey, kid string, claims any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, nil)
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

func keySetOf(key *ecdsa.PrivateKey, kid string) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: kid, Algorithm: "ES256", Use: "sig"}}}
}

// federationStub is a master and one OpenID provider on one server; the handlers read the fields at request time so
// that a test can serve what it wants to see refused.
type federationStub struct {
	*httptest.Server
	masterKey, opKey, jwksKey *ecdsa.PrivateKey

	masterStatement, fetchStatement, opStatement, idpList, signedJwks string
}

func newFederationStub(t *testing.T) *federationStub {
	t.Helper()
	stub := &federationStub{masterKey: newTestKey(t), opKey: newTestKey(t), jwksKey: newTestKey(t)}
	mux := http.NewServeMux()
	serve := func(path string, body *string) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, *body) })
	}
	serve("/.well-known/openid-federation", &stub.masterStatement)
	serve("/fetch", &stub.fetchStatement)
	serve("/idps", &stub.idpList)
	serve("/op/.well-known/openid-federation", &stub.opStatement)
	serve("/op/jwks", &stub.signedJwks)
	stub.Server = httptest.NewServer(mux)
	t.Cleanup(stub.Close)

	lifetime := func(claims map[string]any) map[string]any {
		claims["iat"] = time.Now().Unix()
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		return claims
	}
	stub.masterStatement = signJWS(t, stub.masterKey, "master", lifetime(map[string]any{
		"iss":      stub.URL,
		"sub":      stub.URL,
		"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": stub.URL + "/fetch", "idp_list_endpoint": stub.URL + "/idps"}},
	}))
	stub.fetchStatement = signJWS(t, stub.masterKey, "master", lifetime(map[string]any{
		"iss":  stub.URL,
		"sub":  stub.URL + "/op",
		"jwks": keySetOf(stub.opKey, "op"),
	}))
	stub.opStatement = signJWS(t, stub.opKey, "op", lifetime(map[string]any{
		"iss":  stub.URL + "/op",
		"sub":  stub.URL + "/op",
		"jwks": keySetOf(stub.opKey, "op"),
		"metadata": map[string]any{"openid_provider": map[string]any{
			"issuer":          stub.URL + "/op",
			"signed_jwks_uri": stub.URL + "/op/jwks",
		}},
	}))
	stub.idpList = signJWS(t, stub.masterKey, "master", lifetime(map[string]any{
		"idp_entity": []map[string]any{{"iss": stub.URL + "/op", "organization_name": "OP", "logo_uri": "", "pkv": false, "user_type_supported": "IP"}},
	}))
	stub.signedJwks = signJWS(t, stub.opKey, "op", lifetime(map[string]any{
		"keys": keySetOf(stub.jwksKey, "idtoken").Keys,
	}))
	return stub
}

func (s *federationStub) federation(t *testing.T) *OpenidFederation {
	t.Helper()
	federation, err := NewOpenidFederation(s.URL, keySetOf(s.masterKey, "master"), WithHTTPClient(s.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return federation
}

func TestFederationVerifiesItsWayFromTheTrustAnchorToTheSignedJwks(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)

	idps, err := federation.FetchIdpList()
	if err != nil {
		t.Fatal(err)
	}
	if len(idps) != 1 || idps[0].OrganizationName != "OP" || idps[0].UserType != UserTypeIP {
		t.Fatalf("idps = %+v", idps)
	}

	op, err := federation.FetchEntityStatement(idps[0].Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if op.Issuer != stub.URL+"/op" || len(op.Jwks.Keys.Key("op")) != 1 {
		t.Fatalf("statement = %+v", op)
	}

	jwks, err := federation.FetchSignedJwks(op)
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Key("idtoken")) != 1 {
		t.Fatalf("jwks = %+v", jwks)
	}
}

func TestFederationRefusesMasterStatementNotSignedByTheTrustAnchor(t *testing.T) {
	stub := newFederationStub(t)
	_, err := NewOpenidFederation(stub.URL, keySetOf(newTestKey(t), "master"), WithHTTPClient(stub.Client()))
	if err == nil {
		t.Error("accepted a statement the trust anchor did not sign")
	}
}

func TestFederationRefusesTrustAnchorWithoutAlg(t *testing.T) {
	stub := newFederationStub(t)
	anchor := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: stub.masterKey.Public(), KeyID: "master"}}}
	if _, err := NewOpenidFederation(stub.URL, anchor, WithHTTPClient(stub.Client())); err == nil {
		t.Error("verified with a key that states no alg")
	}
}

func TestFederationRefusesOPStatementNotSignedByTheKeyTheMasterVouchesFor(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	stub.opStatement = signJWS(t, newTestKey(t), "op", map[string]any{"iss": stub.URL + "/op"})
	if _, err := federation.FetchEntityStatement(stub.URL + "/op"); err == nil {
		t.Error("accepted a statement by another key")
	}
}

func TestFederationRefusesMasterStatementThatVouchesForNoKeys(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	stub.fetchStatement = signJWS(t, stub.masterKey, "master", map[string]any{"iss": stub.URL, "sub": stub.URL + "/op"})
	if _, err := federation.FetchEntityStatement(stub.URL + "/op"); err == nil {
		t.Error("went on without keys")
	}
}

func TestFederationRefusesSignedJwksNotSignedByTheStatementsKey(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op, err := federation.FetchEntityStatement(stub.URL + "/op")
	if err != nil {
		t.Fatal(err)
	}
	stub.signedJwks = signJWS(t, newTestKey(t), "op", map[string]any{"keys": []any{}})
	if _, err := federation.FetchSignedJwks(op); err == nil {
		t.Error("accepted a JWKS signed by another key")
	}
}

func TestFederationSignedJwksToleratesSurroundingWhitespace(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op, err := federation.FetchEntityStatement(stub.URL + "/op")
	if err != nil {
		t.Fatal(err)
	}
	stub.signedJwks += "\n"
	if _, err := federation.FetchSignedJwks(op); err != nil {
		t.Error(err)
	}
}

// The clock is 90 seconds ahead when a statement is judged: an iat that far ahead passes, and an exp that near does not.
func TestFederationJudgesStatementsNinetySecondsAhead(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	for _, tc := range []struct {
		name   string
		claims map[string]any
		accept bool
	}{
		{"exp beyond the tolerance", map[string]any{"exp": time.Now().Add(2 * statementClockTolerance).Unix()}, true},
		{"exp within the tolerance", map[string]any{"exp": time.Now().Add(statementClockTolerance / 2).Unix()}, false},
		{"iat within the tolerance", map[string]any{"iat": time.Now().Add(statementClockTolerance / 2).Unix()}, true},
		{"iat beyond the tolerance", map[string]any{"iat": time.Now().Add(2 * statementClockTolerance).Unix()}, false},
		{"nbf beyond the tolerance", map[string]any{"nbf": time.Now().Add(2 * statementClockTolerance).Unix()}, false},
		{"no time claims", map[string]any{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.claims["idp_entity"] = []any{}
			stub.idpList = signJWS(t, stub.masterKey, "master", tc.claims)
			_, err := federation.FetchIdpList()
			if tc.accept && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !tc.accept && err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestFetchIdpListRefusesListWithoutIdpEntity(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	stub.idpList = signJWS(t, stub.masterKey, "master", map[string]any{"iss": stub.URL})
	if _, err := federation.FetchIdpList(); err == nil {
		t.Error("accepted")
	}
}

// loginStub is a federated provider's token endpoint for RelyingPartyClient.ExchangeForIdentity.
type loginStub struct {
	client  *RelyingPartyClient
	encKey  *ecdsa.PrivateKey
	sigKey  *ecdsa.PrivateKey
	idToken string
}

func newLoginStub(t *testing.T) *loginStub {
	t.Helper()
	stub := &loginStub{encKey: newTestKey(t), sigKey: newTestKey(t)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": stub.idToken})
	}))
	t.Cleanup(server.Close)
	stub.client = &RelyingPartyClient{
		rp: &RelyingParty{
			encPrivateKey:   stub.encKey,
			httpClient:      server.Client(),
			entityStatement: &EntityStatement{Subject: "https://rp.example"},
		},
		op: &EntityStatement{
			Issuer:   "https://op.example",
			Metadata: &Metadata{OpenidProvider: &OpenIDProviderMetadata{TokenEndpoint: server.URL}},
		},
		jwks: keySetOf(stub.sigKey, "k"),
	}
	return stub
}

func encryptForTest(t *testing.T, recipient any, alg jose.KeyAlgorithm, enc jose.ContentEncryption, plaintext string) string {
	t.Helper()
	encrypter, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: recipient}, nil)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encrypter.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := encrypted.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (s *loginStub) nestedToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	return encryptForTest(t, s.encKey.Public(), jose.ECDH_ES, jose.A256GCM, signJWS(t, s.sigKey, "k", claims))
}

func validIDTokenClaims() map[string]any {
	return map[string]any{"iss": "https://op.example", "aud": "https://rp.example", "exp": time.Now().Add(time.Hour).Unix()}
}

func TestExchangeDecryptsAndVerifiesTheNestedIDToken(t *testing.T) {
	stub := newLoginStub(t)
	stub.idToken = stub.nestedToken(t, validIDTokenClaims())
	response, err := stub.client.Exchange(t.Context(), oidc.Login{Verifier: "verifier"}, "code")
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := response.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "https://op.example" {
		t.Errorf("iss = %q", claims.Iss)
	}
	if strings.Count(response.IDTokenRaw, ".") != 2 {
		t.Errorf("IDTokenRaw is not the inner JWS: %s", response.IDTokenRaw)
	}
}

func TestExchangeRefusesEncryptionOtherThanRegistered(t *testing.T) {
	stub := newLoginStub(t)
	signed := signJWS(t, stub.sigKey, "k", validIDTokenClaims())
	for name, token := range map[string]string{
		"ECDH-ES+A256KW": encryptForTest(t, stub.encKey.Public(), jose.ECDH_ES_A256KW, jose.A256GCM, signed),
		"A128GCM":        encryptForTest(t, stub.encKey.Public(), jose.ECDH_ES, jose.A128GCM, signed),
		"dir":            encryptForTest(t, make([]byte, 32), jose.DIRECT, jose.A256GCM, signed),
		"not encrypted":  signed,
	} {
		t.Run(name, func(t *testing.T) {
			stub.idToken = token
			if _, err := stub.client.Exchange(t.Context(), oidc.Login{Verifier: "verifier"}, "code"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestExchangeRefusesTokenForAnotherRecipient(t *testing.T) {
	stub := newLoginStub(t)
	stub.idToken = encryptForTest(t, newTestKey(t).Public(), jose.ECDH_ES, jose.A256GCM, signJWS(t, stub.sigKey, "k", validIDTokenClaims()))
	if _, err := stub.client.Exchange(t.Context(), oidc.Login{Verifier: "verifier"}, "code"); err == nil {
		t.Error("accepted")
	}
}

func TestExchangeRefusesIDToken(t *testing.T) {
	stub := newLoginStub(t)
	expired := validIDTokenClaims()
	expired["exp"] = time.Now().Add(-time.Second).Unix()
	otherAudience := validIDTokenClaims()
	otherAudience["aud"] = "https://other.example"
	noAudience := validIDTokenClaims()
	delete(noAudience, "aud")
	for name, token := range map[string]string{
		"expired":             stub.nestedToken(t, expired),
		"for another client":  stub.nestedToken(t, otherAudience),
		"without an audience": stub.nestedToken(t, noAudience),
		"signed by another":   encryptForTest(t, stub.encKey.Public(), jose.ECDH_ES, jose.A256GCM, signJWS(t, newTestKey(t), "k", validIDTokenClaims())),
	} {
		t.Run(name, func(t *testing.T) {
			stub.idToken = token
			if _, err := stub.client.Exchange(t.Context(), oidc.Login{Verifier: "verifier"}, "code"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestSignEntityStatementVerifiesAgainstItsPublishedKey(t *testing.T) {
	key := newTestKey(t)
	rp := &RelyingParty{
		cfg:           &RelyingPartyConfig{FedMasterURL: "https://fedmaster.example"},
		sigPrivateKey: key,
		signKid:       "sign-kid",
		entityStatement: &EntityStatement{
			Issuer:   "https://rp.example",
			Subject:  "https://rp.example",
			Jwks:     &Jwks{Keys: keySetOf(key, "sign-kid")},
			Metadata: &Metadata{OpenidRelyingParty: &OpenIDRelyingPartyMetadata{}},
		},
	}
	signed, err := rp.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := oidc.VerifyJWS(signed, rp.entityStatement.Jwks.Keys, federationKeys)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := parseEntityStatement(payload)
	if err != nil {
		t.Fatal(err)
	}
	if statement.Issuer != "https://rp.example" || statement.Subject != "https://rp.example" {
		t.Errorf("statement = %+v", statement)
	}
	if len(statement.AuthorityHints) != 1 || statement.AuthorityHints[0] != "https://fedmaster.example" {
		t.Errorf("authority_hints = %v", statement.AuthorityHints)
	}
	if statement.Jwks == nil || len(statement.Jwks.Keys.Key("sign-kid")) != 1 {
		t.Errorf("jwks = %+v", statement.Jwks)
	}
	now := time.Now()
	if statement.IssuedAt > now.Add(-59*time.Minute).Unix() || statement.ExpiresAt < now.Add(22*time.Hour).Unix() {
		t.Errorf("iat %d exp %d", statement.IssuedAt, statement.ExpiresAt)
	}
}
