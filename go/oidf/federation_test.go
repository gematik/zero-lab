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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
)

func newTestKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signJWS(t testing.TB, key *ecdsa.PrivateKey, kid string, claims any) string {
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

// testVerifier is a code_verifier as RFC 7636 section 4.1 has it.
const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func keySetOf(key *ecdsa.PrivateKey, kid string) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: kid, Algorithm: "ES256", Use: "sig"}}}
}

// federationStub is a master and one OpenID provider on one server; the handlers read the fields at request time so
// that a test can serve what it wants to see refused.
type federationStub struct {
	*httptest.Server
	masterKey, opKey, jwksKey *ecdsa.PrivateKey

	masterStatement, fetchStatement, opStatement, idpList, signedJwks string
	// idToken is what the provider's token endpoint answers with.
	idToken atomic.Pointer[string]

	// redirected counts the requests that reached /elsewhere, where a redirecting endpoint points.
	redirected atomic.Int64
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
	mux.HandleFunc("POST /op/token", func(w http.ResponseWriter, _ *http.Request) {
		idToken := ""
		if token := stub.idToken.Load(); token != nil {
			idToken = *token
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idToken})
	})
	mux.HandleFunc("/elsewhere", func(http.ResponseWriter, *http.Request) { stub.redirected.Add(1) })
	mux.HandleFunc("/redirecting", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
	stub.Server = httptest.NewTLSServer(mux)
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
			"issuer":                                stub.URL + "/op",
			"signed_jwks_uri":                       stub.URL + "/op/jwks",
			"authorization_endpoint":                stub.URL + "/op/auth",
			"pushed_authorization_request_endpoint": stub.URL + "/op/par",
			"token_endpoint":                        stub.URL + "/op/token",
		}},
	}))
	stub.idpList = signJWS(t, stub.masterKey, "master", lifetime(map[string]any{
		"iss":        stub.URL,
		"idp_entity": []map[string]any{{"iss": stub.URL + "/op", "organization_name": "OP", "logo_uri": "", "pkv": false, "user_type_supported": "IP"}},
	}))
	stub.signedJwks = signJWS(t, stub.opKey, "op", lifetime(map[string]any{
		"keys": keySetOf(stub.jwksKey, "idtoken").Keys,
	}))
	return stub
}

func (s *federationStub) federation(t *testing.T) *OpenidFederation {
	t.Helper()
	federation, err := NewOpenidFederation(t.Context(), s.URL, keySetOf(s.masterKey, "master"), WithHTTPClient(s.Client()), WithDocuments(NewMemoryDocuments(16, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return federation
}

func TestFederationVerifiesItsWayFromTheTrustAnchorToTheSignedJwks(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)

	idps, err := federation.FetchIdpList(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(idps) != 1 || idps[0].OrganizationName != "OP" || idps[0].UserType != UserTypeIP {
		t.Fatalf("idps = %+v", idps)
	}

	op, err := federation.FetchEntityStatement(t.Context(), idps[0].Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if op.Issuer != stub.URL+"/op" || len(op.Jwks.Keys.Key("op")) != 1 {
		t.Fatalf("statement = %+v", op)
	}

	jwks, err := federation.FetchSignedJwks(t.Context(), op)
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Key("idtoken")) != 1 {
		t.Fatalf("jwks = %+v", jwks)
	}
}

func TestOIDF_10_2_AMasterStatementNotSignedByTheTrustAnchorIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	_, err := NewOpenidFederation(t.Context(), stub.URL, keySetOf(newTestKey(t), "master"), WithHTTPClient(stub.Client()), WithDocuments(NewMemoryDocuments(16, nil)))
	if err == nil {
		t.Error("accepted a statement the trust anchor did not sign")
	}
}

func TestFederationRefusesTrustAnchorWithoutAlg(t *testing.T) {
	stub := newFederationStub(t)
	anchor := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: stub.masterKey.Public(), KeyID: "master"}}}
	if _, err := NewOpenidFederation(t.Context(), stub.URL, anchor, WithHTTPClient(stub.Client()), WithDocuments(NewMemoryDocuments(16, nil))); err == nil {
		t.Error("verified with a key that states no alg")
	}
}

func TestOIDF_10_2_AnOPStatementNotSignedByTheKeyTheMasterVouchesForIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	stub.opStatement = signJWS(t, newTestKey(t), "op", map[string]any{"iss": stub.URL + "/op"})
	if _, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op"); err == nil {
		t.Error("accepted a statement by another key")
	}
}

func TestOIDF_3_2_AMasterStatementThatVouchesForNoKeysIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	stub.fetchStatement = signJWS(t, stub.masterKey, "master", map[string]any{"iss": stub.URL, "sub": stub.URL + "/op"})
	if _, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op"); err == nil || !strings.Contains(err.Error(), "vouches for no keys") {
		t.Errorf("went on without keys: %v", err)
	}
}

func TestOIDF_5_2_1_ASignedJwksNotSignedByTheStatementsKeyIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	stub.signedJwks = signJWS(t, newTestKey(t), "op", map[string]any{"keys": []any{}})
	if _, err := federation.FetchSignedJwks(t.Context(), op); err == nil {
		t.Error("accepted a JWKS signed by another key")
	}
}

func TestFederationSignedJwksToleratesSurroundingWhitespace(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	stub.signedJwks += "\n"
	if _, err := federation.FetchSignedJwks(t.Context(), op); err != nil {
		t.Error(err)
	}
}

// The clock is 90 seconds ahead when a statement is judged: an iat that far ahead passes, and an exp that near does not.
func TestFederationJudgesStatementsNinetySecondsAhead(t *testing.T) {
	stub := newFederationStub(t)
	hour := time.Now().Add(time.Hour).Unix()
	for _, tc := range []struct {
		name   string
		claims map[string]any
		// want is why the list is refused, nil when it is taken; reason is the message of a refusal without sentinel.
		want   error
		reason string
	}{
		{"exp beyond the tolerance", map[string]any{"exp": time.Now().Add(2 * statementClockTolerance).Unix()}, nil, ""},
		{"exp within the tolerance", map[string]any{"exp": time.Now().Add(statementClockTolerance / 2).Unix()}, openid.ErrTokenExpired, ""},
		{"iat within the tolerance", map[string]any{"iat": time.Now().Add(statementClockTolerance / 2).Unix(), "exp": hour}, nil, ""},
		{"iat beyond the tolerance", map[string]any{"iat": time.Now().Add(2 * statementClockTolerance).Unix(), "exp": hour}, openid.ErrTokenIssuedInFuture, ""},
		{"nbf beyond the tolerance", map[string]any{"nbf": time.Now().Add(2 * statementClockTolerance).Unix(), "exp": hour}, openid.ErrTokenNotYetValid, ""},
		{"no exp", map[string]any{}, nil, "has to state its exp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.claims["idp_entity"] = []any{}
			tc.claims["iss"] = stub.URL
			stub.idpList = signJWS(t, stub.masterKey, "master", tc.claims)
			_, err := stub.federation(t).FetchIdpList(t.Context())
			switch {
			case tc.want != nil:
				if !errors.Is(err, tc.want) {
					t.Errorf("err = %v, want %v", err, tc.want)
				}
			case tc.reason != "":
				if err == nil || !strings.Contains(err.Error(), tc.reason) {
					t.Errorf("err = %v, want %q", err, tc.reason)
				}
			case err != nil:
				t.Errorf("refused: %v", err)
			}
		})
	}
}

func TestFetchIdpListRefusesListWithoutIdpEntity(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	stub.idpList = signJWS(t, stub.masterKey, "master", map[string]any{"iss": stub.URL})
	if _, err := federation.FetchIdpList(t.Context()); err == nil {
		t.Error("accepted")
	}
}

// loginStub is a relying party built by New and a client of the federated provider https://op.example, whose
// federation, master https://fedmaster.example included, is served in memory. The provider's PAR endpoint answers
// with a request_uri and its token endpoint with idToken and scope, until a test hands the endpoints a handler of its
// own.
type loginStub struct {
	client  *RelyingPartyClient
	encKey  *ecdsa.PrivateKey
	sigKey  *ecdsa.PrivateKey
	idToken string
	// scope is the scope of the token response.
	scope string

	masterKey, opKey *ecdsa.PrivateKey
	// endpoints answers the provider's PAR and token endpoints when set.
	endpoints http.Handler
	// opStatement and signedJwks are what the provider publishes; publish signs them anew.
	opStatement, signedJwks string
	transport               inMemory
}

const (
	loginStubMaster = "https://fedmaster.example"
	loginStubOP     = "https://op.example"
)

func newLoginStub(tb testing.TB) *loginStub {
	tb.Helper()
	return newLoginStubWith(tb, nil)
}

// newLoginStubWith builds the loginStub's relying party with its config changed first.
func newLoginStubWith(tb testing.TB, change func(*RelyingPartyConfig)) *loginStub {
	tb.Helper()
	stub := &loginStub{encKey: newTestKey(tb), sigKey: newTestKey(tb), masterKey: newTestKey(tb), opKey: newTestKey(tb)}
	lifetime := func(claims map[string]any) map[string]any {
		claims["iat"] = time.Now().Unix()
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		return claims
	}
	masterStatement := signJWS(tb, stub.masterKey, "master", lifetime(map[string]any{
		"iss": loginStubMaster, "sub": loginStubMaster,
		"metadata": map[string]any{"federation_entity": map[string]any{
			"federation_fetch_endpoint": loginStubMaster + "/fetch", "idp_list_endpoint": loginStubMaster + "/idps",
		}},
	}))
	fetchStatement := signJWS(tb, stub.masterKey, "master", lifetime(map[string]any{
		"iss": loginStubMaster, "sub": loginStubOP, "jwks": keySetOf(stub.opKey, "op"),
	}))
	idpList := signJWS(tb, stub.masterKey, "master", lifetime(map[string]any{
		"iss":        loginStubMaster,
		"idp_entity": []map[string]any{{"iss": loginStubOP, "organization_name": "OP", "logo_uri": "", "pkv": false, "user_type_supported": "IP"}},
	}))
	stub.publish(tb, nil, keySetOf(stub.sigKey, "k"))

	mux := http.NewServeMux()
	serve := func(pattern string, body func() string) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body()) })
	}
	serve("GET fedmaster.example/.well-known/openid-federation", func() string { return masterStatement })
	serve("GET fedmaster.example/fetch", func() string { return fetchStatement })
	serve("GET fedmaster.example/idps", func() string { return idpList })
	serve("GET op.example/.well-known/openid-federation", func() string { return stub.opStatement })
	serve("GET op.example/jwks", func() string { return stub.signedJwks })
	mux.HandleFunc("POST op.example/", func(w http.ResponseWriter, r *http.Request) {
		if stub.endpoints != nil {
			stub.endpoints.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/par" {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"request_uri":"urn:r","expires_in":60}`)
			return
		}
		response := map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": stub.idToken}
		if stub.scope != "" {
			response["scope"] = stub.scope
		}
		_ = json.MarshalWrite(w, response)
	})
	stub.transport = inMemory{handler: mux}

	master := &Jwk{Key: &keySetOf(stub.masterKey, "master").Keys[0]}
	cfg := &RelyingPartyConfig{
		Subject:          "https://rp.example",
		FedMasterURL:     loginStubMaster,
		FedMasterJWK:     master,
		RelyingParty:     testRelyingPartyMetadata(),
		FederationEntity: testFederationEntity(),
		HTTPClient:       &http.Client{Transport: stub.transport},
		Documents:        NewMemoryDocuments(16, nil),
	}
	if change != nil {
		change(cfg)
	}
	keys := newTestKeys(tb)
	keys.Decrypt, keys.DecryptKID = ecdhKey(tb, stub.encKey), "enc"
	rp, err := New(tb.Context(), cfg, keys)
	if err != nil {
		tb.Fatal(err)
	}
	// New layers mutual TLS onto a network transport; the provider's endpoints are served in memory as well.
	rp.httpClient = &http.Client{Transport: stub.transport, CheckRedirect: refuseRedirect}
	if stub.client, err = rp.Client(tb.Context(), loginStubOP); err != nil {
		tb.Fatal(err)
	}
	return stub
}

// publish makes the provider publish its openid_provider metadata, changed by change, and jwks as its signed JWKS. The
// relying party's store is emptied, so that its next call reads what was published.
func (s *loginStub) publish(tb testing.TB, change func(metadata map[string]any), jwks *jose.JSONWebKeySet) {
	tb.Helper()
	metadata := map[string]any{
		"issuer":                                loginStubOP,
		"signed_jwks_uri":                       loginStubOP + "/jwks",
		"authorization_endpoint":                loginStubOP + "/auth",
		"pushed_authorization_request_endpoint": loginStubOP + "/par",
		"token_endpoint":                        loginStubOP + "/token",
	}
	if change != nil {
		change(metadata)
	}
	now := time.Now()
	s.opStatement = signJWS(tb, s.opKey, "op", map[string]any{
		"iss": loginStubOP, "sub": loginStubOP, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": keySetOf(s.opKey, "op"), "metadata": map[string]any{"openid_provider": metadata},
	})
	s.signedJwks = signJWS(tb, s.opKey, "op", map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "keys": jwks.Keys})
	if s.client != nil {
		s.client.rp.federation.documents = NewMemoryDocuments(16, nil)
	}
}

func encryptForTest(t testing.TB, recipient any, alg jose.KeyAlgorithm, enc jose.ContentEncryption, plaintext string) string {
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
	return map[string]any{
		"iss": "https://op.example", "aud": "https://rp.example", "nonce": "n", "exp": time.Now().Add(time.Hour).Unix(),
		"sub": "subject", "acr": LoAHigh, "amr": []string{"urn:telematik:auth:eGK"}, "auth_time": time.Now().Add(-time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
}

// OIDC Core 3.1.3.7 step 1: decrypt with the algorithms registered; a token not encrypted as registered is refused.
func TestOIDCCore_3_1_3_7_1_EncryptionOtherThanRegisteredIsRefused(t *testing.T) {
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
			if _, err := stub.client.Exchange(t.Context(), openid.Login{Nonce: "n", Verifier: testVerifier}, "code"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// gemSpec_IDP_FD A_23195.
func TestA_23195_ATokenEncryptedForAnotherRecipientIsRefused(t *testing.T) {
	stub := newLoginStub(t)
	stub.idToken = encryptForTest(t, newTestKey(t).Public(), jose.ECDH_ES, jose.A256GCM, signJWS(t, stub.sigKey, "k", validIDTokenClaims()))
	if _, err := stub.client.Exchange(t.Context(), openid.Login{Nonce: "n", Verifier: testVerifier}, "code"); err == nil {
		t.Error("accepted")
	}
}

// gemSpec_IDP_FD A_23049, OIDC Core 3.1.3.7 steps 3, 6 and 9: audience, signature and lifetime.
func TestA_23049_AnIDTokenThatDoesNotHoldIsRefused(t *testing.T) {
	stub := newLoginStub(t)
	expired := validIDTokenClaims()
	expired["exp"] = time.Now().Add(-idTokenSkew - time.Second).Unix()
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
			if _, err := stub.client.Exchange(t.Context(), openid.Login{Nonce: "n", Verifier: testVerifier}, "code"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestSignEntityStatementVerifiesAgainstItsPublishedKey(t *testing.T) {
	rp := literalRelyingParty(t, newTestKey(t))
	signed, err := rp.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := openid.VerifyJWS(signed, rp.entityStatement.Jwks.Keys, trustAnchorKeys)
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

// opClaims is what the federation stub's OP publishes, with its lifetime, for a test to change.
func (s *federationStub) opClaims(overrides map[string]any) map[string]any {
	op := s.URL + "/op"
	claims := map[string]any{
		"iss":  op,
		"sub":  op,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
		"jwks": keySetOf(s.opKey, "op"),
	}
	metadata := map[string]any{
		"issuer":                                op,
		"signed_jwks_uri":                       op + "/jwks",
		"authorization_endpoint":                op + "/auth",
		"pushed_authorization_request_endpoint": op + "/par",
		"token_endpoint":                        op + "/token",
	}
	for name, value := range overrides {
		if _, ok := metadata[name]; ok {
			metadata[name] = value
		} else {
			claims[name] = value
		}
	}
	claims["metadata"] = map[string]any{"openid_provider": metadata}
	return claims
}

// relyingParty is a relying party of the stub's federation, built by New.
func (s *federationStub) relyingParty(t *testing.T) *RelyingParty {
	t.Helper()
	return s.relyingPartyWith(t, newTestKeys(t), nil)
}

// relyingPartyWith builds a relying party of the stub's federation with keys and the config changed first.
func (s *federationStub) relyingPartyWith(t *testing.T, keys Keys, change func(*RelyingPartyConfig)) *RelyingParty {
	t.Helper()
	cfg := &RelyingPartyConfig{
		Subject:          "https://rp.example",
		FedMasterURL:     s.URL,
		FedMasterJWK:     &Jwk{Key: &keySetOf(s.masterKey, "master").Keys[0]},
		RelyingParty:     testRelyingPartyMetadata(),
		FederationEntity: testFederationEntity(),
		HTTPClient:       s.Client(),
		Documents:        NewMemoryDocuments(16, nil),
	}
	if change != nil {
		change(cfg)
	}
	rp, err := New(t.Context(), cfg, keys)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

func TestOIDF_10_2_AMasterStatementNamingAnotherMasterIsRefused(t *testing.T) {
	for name, claims := range map[string]map[string]any{
		"issuer":  {"iss": "https://other.example", "sub": nil},
		"subject": {"iss": nil, "sub": "https://other.example"},
	} {
		t.Run(name, func(t *testing.T) {
			stub := newFederationStub(t)
			for member, value := range claims {
				if value == nil {
					claims[member] = stub.URL
				}
			}
			claims["metadata"] = map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": stub.URL + "/fetch"}}
			stub.masterStatement = signJWS(t, stub.masterKey, "master", claims)
			if _, err := NewOpenidFederation(t.Context(), stub.URL, keySetOf(stub.masterKey, "master"), WithHTTPClient(stub.Client()), WithDocuments(NewMemoryDocuments(16, nil))); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// Without the comparison the master's word about one member would hand any other member's issuer its keys.
func TestOIDF_10_2_AMasterStatementAboutAnotherEntityIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	for name, claims := range map[string]map[string]any{
		"another subject": {"iss": stub.URL, "sub": stub.URL + "/other", "jwks": keySetOf(stub.opKey, "op")},
		"another issuer":  {"iss": "https://other.example", "sub": stub.URL + "/op", "jwks": keySetOf(stub.opKey, "op")},
	} {
		t.Run(name, func(t *testing.T) {
			stub.fetchStatement = signJWS(t, stub.masterKey, "master", claims)
			if _, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestOIDF_10_2_ASelfSignedStatementOfAnotherEntityIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	for name, overrides := range map[string]map[string]any{
		"another issuer":  {"iss": "https://other.example"},
		"another subject": {"sub": "https://other.example"},
	} {
		t.Run(name, func(t *testing.T) {
			stub.opStatement = signJWS(t, stub.opKey, "op", stub.opClaims(overrides))
			if _, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// The request's idp_iss arrives here, so nothing goes out for an issuer that cannot be an entity identifier.
func TestOIDF_1_2_NobodyIsAskedAboutAnIssuerThatIsNoHTTPSEntityIdentifier(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	var fetches atomic.Int64
	counting := stub.Config.Handler
	stub.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		counting.ServeHTTP(w, r)
	})
	for _, iss := range []string{"", "http://op.example", "ftp://op.example", "op.example", "https://", "https://user@op.example", "https://op.example?x=1", "https://op.example#x"} {
		if _, err := federation.FetchEntityStatement(t.Context(), iss); err == nil {
			t.Errorf("%q accepted", iss)
		}
	}
	if n := fetches.Load(); n != 0 {
		t.Errorf("%d fetches", n)
	}
}

func TestOIDF_1_2_APlainHTTPMasterIsRefused(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	_, err := NewOpenidFederation(t.Context(), plain.URL, keySetOf(newTestKey(t), "master"), WithHTTPClient(plain.Client()), WithDocuments(NewMemoryDocuments(16, nil)))
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v", err)
	}
}

func TestOIDF_5_1_1_TheMastersEndpointsAreFetchedOverHTTPSOnly(t *testing.T) {
	for name, fetch := range map[string]func(*OpenidFederation, string) error{
		"federation_fetch_endpoint": func(f *OpenidFederation, iss string) error {
			_, err := f.FetchEntityStatement(t.Context(), iss)
			return err
		},
		"idp_list_endpoint": func(f *OpenidFederation, _ string) error {
			_, err := f.FetchIdpList(t.Context())
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			stub := newFederationStub(t)
			endpoints := map[string]any{"federation_fetch_endpoint": stub.URL + "/fetch", "idp_list_endpoint": stub.URL + "/idps"}
			endpoints[name] = "http" + strings.TrimPrefix(stub.URL, "https") + "/plain"
			stub.masterStatement = signJWS(t, stub.masterKey, "master", map[string]any{"iss": stub.URL, "sub": stub.URL, "metadata": map[string]any{"federation_entity": endpoints}})
			err := fetch(stub.federation(t), stub.URL+"/op")
			if err == nil || !strings.Contains(err.Error(), "https") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// Server rule 2: outbound fetches go only to trust-chain-derived hosts, which a redirect would leave.
func TestServerRule2_FederationDoesNotFollowARedirect(t *testing.T) {
	stub := newFederationStub(t)
	endpoints := map[string]any{"federation_fetch_endpoint": stub.URL + "/redirecting", "idp_list_endpoint": stub.URL + "/redirecting"}
	stub.masterStatement = signJWS(t, stub.masterKey, "master", map[string]any{"iss": stub.URL, "sub": stub.URL, "metadata": map[string]any{"federation_entity": endpoints}})
	federation := stub.federation(t)
	if _, err := federation.FetchIdpList(t.Context()); err == nil {
		t.Error("list accepted")
	}
	if _, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op"); err == nil {
		t.Error("statement accepted")
	}
	if n := stub.redirected.Load(); n != 0 {
		t.Errorf("%d requests followed a redirect", n)
	}
}

func TestOIDF_5_2_1_FetchSignedJwksTakesAnHTTPSURIOnly(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op := &EntityStatement{
		Jwks:     &Jwks{Keys: keySetOf(stub.opKey, "op")},
		Metadata: &Metadata{OpenidProvider: &OpenIDProviderMetadata{SignedJwksURI: "http" + strings.TrimPrefix(stub.URL, "https") + "/op/jwks"}},
	}
	if _, err := federation.FetchSignedJwks(t.Context(), op); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v", err)
	}
}

func TestServerRule2_FetchSignedJwksDoesNotFollowARedirect(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op := &EntityStatement{
		Jwks:     &Jwks{Keys: keySetOf(stub.opKey, "op")},
		Metadata: &Metadata{OpenidProvider: &OpenIDProviderMetadata{SignedJwksURI: stub.URL + "/redirecting"}},
	}
	if _, err := federation.FetchSignedJwks(t.Context(), op); err == nil {
		t.Error("accepted")
	}
	if n := stub.redirected.Load(); n != 0 {
		t.Errorf("%d requests followed a redirect", n)
	}
}

// OpenID Federation 5.2.1 leaves exp of a signed JWK Set optional. A set without it is bound to the call that fetched
// it: it is not kept, so the set a provider has replaced is not served again.
func TestOIDF_5_2_1_ASignedJwksWithoutExpIsTakenAndNeverKept(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	fetches := stub.countFetches()
	op, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}

	stub.signedJwks = signJWS(t, stub.opKey, "op", map[string]any{
		"iss": stub.URL + "/op", "iat": time.Now().Unix(), "keys": keySetOf(stub.jwksKey, "idtoken").Keys,
	})
	jwks, err := federation.FetchSignedJwks(t.Context(), op)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if len(jwks.Key("idtoken")) != 1 {
		t.Fatalf("jwks = %+v", jwks)
	}

	stub.signedJwks = signJWS(t, stub.opKey, "op", map[string]any{
		"iss": stub.URL + "/op", "iat": time.Now().Unix(), "keys": keySetOf(newTestKey(t), "rotated").Keys,
	})
	jwks, err = federation.FetchSignedJwks(t.Context(), op)
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Key("rotated")) != 1 || len(jwks.Key("idtoken")) != 0 {
		t.Errorf("the replaced key set was served again: %+v", jwks)
	}
	if n := fetches.count("/op/jwks"); n != 2 {
		t.Errorf("%d fetches of the signed JWKS, want one per call", n)
	}
}

func TestOIDF_5_2_1_ASignedJwksOutsideItsLifetimeIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	keys := keySetOf(stub.jwksKey, "idtoken").Keys
	for name, claims := range map[string]map[string]any{
		"expired":       {"keys": keys, "exp": time.Now().Add(-time.Hour).Unix()},
		"expires soon":  {"keys": keys, "exp": time.Now().Add(statementClockTolerance / 2).Unix()},
		"not yet valid": {"keys": keys, "exp": time.Now().Add(2 * time.Hour).Unix(), "nbf": time.Now().Add(time.Hour).Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			stub.signedJwks = signJWS(t, stub.opKey, "op", claims)
			if _, err := federation.FetchSignedJwks(t.Context(), op); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestServerRule2_FederationReadsNoMoreThanItsBound(t *testing.T) {
	stub := newFederationStub(t)
	op, err := stub.federation(t).FetchEntityStatement(t.Context(), stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	federation := stub.federation(t)
	huge := strings.Repeat(" ", maxFederationResponseBytes) + stub.signedJwks
	stub.signedJwks, stub.idpList, stub.fetchStatement = huge, huge, huge
	for name, fetch := range map[string]func() error{
		"signed JWKS": func() error { _, err := federation.FetchSignedJwks(t.Context(), op); return err },
		"IdP list":    func() error { _, err := federation.FetchIdpList(t.Context()); return err },
		"statement":   func() error { _, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op"); return err },
	} {
		if err := fetch(); err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRelyingPartyTakesAProviderWhoseEndpointsAreAllHTTPS(t *testing.T) {
	stub := newFederationStub(t)
	if _, err := stub.relyingParty(t).Client(t.Context(), stub.URL+"/op"); err != nil {
		t.Fatal(err)
	}
}

func TestRelyingPartyRefusesAProviderWithAnEndpointThatIsNotHTTPS(t *testing.T) {
	for _, endpoint := range []string{"authorization_endpoint", "pushed_authorization_request_endpoint", "token_endpoint"} {
		t.Run(endpoint, func(t *testing.T) {
			stub := newFederationStub(t)
			stub.opStatement = signJWS(t, stub.opKey, "op", stub.opClaims(map[string]any{endpoint: "http://op.example/plain"}))
			if _, err := stub.relyingParty(t).Client(t.Context(), stub.URL+"/op"); err == nil || !strings.Contains(err.Error(), endpoint) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// The relying party's client carries its mTLS key, which a redirect would present elsewhere.
func TestRelyingPartyDoesNotFollowARedirectFromPARNorTheTokenEndpoint(t *testing.T) {
	rp, err := New(t.Context(), testRelyingPartyConfig(t, newFederationStub(t)), newTestKeys(t))
	if err != nil {
		t.Fatal(err)
	}
	if rp.httpClient.CheckRedirect == nil || rp.httpClient.CheckRedirect(nil, nil) == nil {
		t.Error("the mTLS client follows redirects")
	}
}

// Server rules 5 and 14. A provider's refusal may echo what it was sent, and the statement fetch's failure body comes
// from outside.
func TestServerRule14_AFederatedLoginLogsNoSecretAtDebug(t *testing.T) {
	const (
		state, nonce, verifier = "state-value", "nonce-value", "verifier-value-0123456789abcdefghijklmnopqrstuvwxyz"
		code, requestURI       = "code-value", "urn:request-uri-value"
		token                  = "access-token-value"
	)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	refusal := fmt.Sprintf(`{"error":"invalid_request","errorDescription":"state %s nonce %s verifier %s code %s"}`, state, nonce, verifier, code)
	var refuse atomic.Bool
	stub := newLoginStub(t)
	stub.endpoints = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if refuse.Load() {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, refusal)
			return
		}
		switch r.URL.Path {
		case "/par":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"request_uri":%q,"expires_in":60}`, requestURI)
		default:
			_ = json.MarshalWrite(w, map[string]any{"access_token": token, "token_type": "Bearer", "id_token": stub.idToken})
		}
	})
	claims := validIDTokenClaims()
	claims["nonce"] = nonce
	stub.idToken = stub.nestedToken(t, claims)

	login := openid.Login{State: state, Nonce: nonce, Verifier: verifier}
	if _, err := stub.client.AuthenticationURL(t.Context(), login); err != nil {
		t.Fatal(err)
	}
	if _, err := stub.client.Exchange(t.Context(), login, code); err != nil {
		t.Fatal(err)
	}
	refuse.Store(true)
	if _, err := stub.client.AuthenticationURL(t.Context(), login); err == nil {
		t.Fatal("the refusal went unnoticed")
	}
	if _, err := stub.client.Exchange(t.Context(), login, code); err == nil {
		t.Fatal("the refusal went unnoticed")
	}

	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, code)
	}))
	defer failing.Close()
	if _, err := NewOpenidFederation(t.Context(), failing.URL, keySetOf(newTestKey(t), "master"), WithHTTPClient(failing.Client()), WithDocuments(NewMemoryDocuments(16, nil))); err == nil {
		t.Fatal("the failure went unnoticed")
	}

	for _, value := range []string{state, nonce, verifier, code, requestURI, token, stub.idToken} {
		if strings.Contains(logs.String(), value) {
			t.Errorf("the log holds %q:\n%s", value, logs.String())
		}
	}
}

// testRelyingPartyConfig is a relying party of the stub's federation, for New with keys such as newTestKeys.
func testRelyingPartyConfig(t *testing.T, stub *federationStub) *RelyingPartyConfig {
	t.Helper()
	return &RelyingPartyConfig{
		Subject:          "https://rp.example",
		FedMasterURL:     stub.URL,
		FedMasterJWK:     &Jwk{Key: &keySetOf(stub.masterKey, "master").Keys[0]},
		RelyingParty:     testRelyingPartyMetadata(),
		FederationEntity: testFederationEntity(),
		HTTPClient:       stub.Client(),
		Documents:        NewMemoryDocuments(16, nil),
	}
}

func withoutAlg(set *jose.JSONWebKeySet) *jose.JSONWebKeySet {
	set.Keys[0].Algorithm = ""
	return set
}

// T-Systems' IdPs in the reference federation publish every key without alg, which RFC 7517 section 4.4 leaves optional.
func TestRFC7517_4_4_FederationAcceptsMemberKeysWithoutAlg(t *testing.T) {
	stub := newFederationStub(t)
	lifetime := func(claims map[string]any) map[string]any {
		claims["iat"], claims["exp"] = time.Now().Unix(), time.Now().Add(time.Hour).Unix()
		return claims
	}
	stub.fetchStatement = signJWS(t, stub.masterKey, "master", lifetime(map[string]any{
		"iss": stub.URL, "sub": stub.URL + "/op", "jwks": withoutAlg(keySetOf(stub.opKey, "op")),
	}))
	stub.opStatement = signJWS(t, stub.opKey, "op", lifetime(map[string]any{
		"iss": stub.URL + "/op", "sub": stub.URL + "/op", "jwks": withoutAlg(keySetOf(stub.opKey, "op")),
		"metadata": map[string]any{"openid_provider": map[string]any{"signed_jwks_uri": stub.URL + "/op/jwks"}},
	}))
	federation := stub.federation(t)
	op, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := federation.FetchSignedJwks(t.Context(), op); err != nil {
		t.Fatal(err)
	}
}

// RFC 8725 Section 3.1: each key is used with exactly one algorithm. Without an alg on the key, its type and curve
// still leave the token one algorithm.
func TestRFC8725_3_1_AMemberTokenWhoseAlgDoesNotFitTheKeyWithoutAlgIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	stub.fetchStatement = signJWS(t, stub.masterKey, "master", map[string]any{
		"iss": stub.URL, "sub": stub.URL + "/op", "exp": time.Now().Add(time.Hour).Unix(),
		"jwks": withoutAlg(keySetOf(stub.opKey, "op")),
	})
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: other}, (&jose.SignerOptions{}).WithHeader("kid", "op"))
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign([]byte(`{"iss":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if stub.opStatement, err = object.CompactSerialize(); err != nil {
		t.Fatal(err)
	}
	if _, err := stub.federation(t).FetchEntityStatement(t.Context(), stub.URL+"/op"); err == nil || !strings.Contains(err.Error(), "of another type or curve than the token's alg needs") {
		t.Errorf("not refused for its algorithm: %v", err)
	}
}

func TestRFC7517_4_4_AnIDTokenIsVerifiedWithAKeyWithoutAlg(t *testing.T) {
	stub := newLoginStub(t)
	stub.publish(t, nil, withoutAlg(keySetOf(stub.sigKey, "k")))
	stub.idToken = stub.nestedToken(t, validIDTokenClaims())
	if _, err := stub.client.Exchange(t.Context(), openid.Login{Nonce: "n", Verifier: testVerifier}, "code"); err != nil {
		t.Fatal(err)
	}
}

// OpenID Federation 1.1 section 5.2.1 types a signed JWKS jwk-set+jwt; what an IDP publishes is trusted for its
// signature along the chain, so a missing or other typ does not keep its keys from being read.
func TestOIDF_5_2_1_AnIDPsSignedJwksIsReadWhateverItsTyp(t *testing.T) {
	for _, typ := range []string{"jwk-set+jwt", "jwk-set+json", "JWT", ""} {
		stub := newFederationStub(t)
		options := &jose.SignerOptions{}
		if typ != "" {
			options = options.WithType(jose.ContentType(typ))
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: stub.opKey, KeyID: "op"}}, options)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "keys": keySetOf(stub.jwksKey, "idtoken").Keys})
		if err != nil {
			t.Fatal(err)
		}
		object, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		if stub.signedJwks, err = object.CompactSerialize(); err != nil {
			t.Fatal(err)
		}
		federation := stub.federation(t)
		op, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op")
		if err != nil {
			t.Fatal(err)
		}
		if keys, err := federation.FetchSignedJwks(t.Context(), op); err != nil || len(keys.Key("idtoken")) != 1 {
			t.Errorf("typ %q: %v", typ, err)
		}
	}
}
