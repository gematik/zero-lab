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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	if _, err := federation.FetchEntityStatement(stub.URL + "/op"); err == nil || !strings.Contains(err.Error(), "vouches for no keys") {
		t.Errorf("went on without keys: %v", err)
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
	return map[string]any{"iss": "https://op.example", "aud": "https://rp.example", "nonce": "n", "exp": time.Now().Add(time.Hour).Unix()}
}

func TestExchangeDecryptsAndVerifiesTheNestedIDToken(t *testing.T) {
	stub := newLoginStub(t)
	stub.idToken = stub.nestedToken(t, validIDTokenClaims())
	response, err := stub.client.Exchange(t.Context(), oidc.Login{Nonce: "n", Verifier: "verifier"}, "code")
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
			if _, err := stub.client.Exchange(t.Context(), oidc.Login{Nonce: "n", Verifier: "verifier"}, "code"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestExchangeRefusesTokenForAnotherRecipient(t *testing.T) {
	stub := newLoginStub(t)
	stub.idToken = encryptForTest(t, newTestKey(t).Public(), jose.ECDH_ES, jose.A256GCM, signJWS(t, stub.sigKey, "k", validIDTokenClaims()))
	if _, err := stub.client.Exchange(t.Context(), oidc.Login{Nonce: "n", Verifier: "verifier"}, "code"); err == nil {
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
			if _, err := stub.client.Exchange(t.Context(), oidc.Login{Nonce: "n", Verifier: "verifier"}, "code"); err == nil {
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
	payload, err := oidc.VerifyJWS(signed, rp.entityStatement.Jwks.Keys, trustAnchorKeys)
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

func (s *federationStub) relyingParty(t *testing.T) *RelyingParty {
	t.Helper()
	return &RelyingParty{
		cfg:        &RelyingPartyConfig{},
		federation: s.federation(t),
		httpClient: s.Client(),
		entityStatement: &EntityStatement{
			Subject:  "https://rp.example",
			Metadata: &Metadata{OpenidRelyingParty: &OpenIDRelyingPartyMetadata{RedirectURIs: []string{"https://rp.example/cb"}}},
		},
	}
}

func TestFederationRefusesAMasterStatementNamingAnotherMaster(t *testing.T) {
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
			if _, err := NewOpenidFederation(stub.URL, keySetOf(stub.masterKey, "master"), WithHTTPClient(stub.Client())); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// Without the comparison the master's word about one member would hand any other member's issuer its keys.
func TestFederationRefusesAMasterStatementAboutAnotherEntity(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	for name, claims := range map[string]map[string]any{
		"another subject": {"iss": stub.URL, "sub": stub.URL + "/other", "jwks": keySetOf(stub.opKey, "op")},
		"another issuer":  {"iss": "https://other.example", "sub": stub.URL + "/op", "jwks": keySetOf(stub.opKey, "op")},
	} {
		t.Run(name, func(t *testing.T) {
			stub.fetchStatement = signJWS(t, stub.masterKey, "master", claims)
			if _, err := federation.FetchEntityStatement(stub.URL + "/op"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestFederationRefusesASelfSignedStatementOfAnotherEntity(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	for name, overrides := range map[string]map[string]any{
		"another issuer":  {"iss": "https://other.example"},
		"another subject": {"sub": "https://other.example"},
	} {
		t.Run(name, func(t *testing.T) {
			stub.opStatement = signJWS(t, stub.opKey, "op", stub.opClaims(overrides))
			if _, err := federation.FetchEntityStatement(stub.URL + "/op"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// The request's idp_iss arrives here, so nothing goes out for an issuer that cannot be an entity identifier.
func TestFederationAsksNobodyAboutAnIssuerThatIsNoHTTPSEntityIdentifier(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	var fetches atomic.Int64
	counting := stub.Config.Handler
	stub.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		counting.ServeHTTP(w, r)
	})
	for _, iss := range []string{"", "http://op.example", "ftp://op.example", "op.example", "https://", "https://user@op.example", "https://op.example?x=1", "https://op.example#x"} {
		if _, err := federation.FetchEntityStatement(iss); err == nil {
			t.Errorf("%q accepted", iss)
		}
	}
	if n := fetches.Load(); n != 0 {
		t.Errorf("%d fetches", n)
	}
}

func TestFederationRefusesAPlainHTTPMaster(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	_, err := NewOpenidFederation(plain.URL, keySetOf(newTestKey(t), "master"), WithHTTPClient(plain.Client()))
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v", err)
	}
}

func TestFederationFetchesTheMastersEndpointsOverHTTPSOnly(t *testing.T) {
	for name, fetch := range map[string]func(*OpenidFederation, string) error{
		"federation_fetch_endpoint": func(f *OpenidFederation, iss string) error {
			_, err := f.FetchEntityStatement(iss)
			return err
		},
		"idp_list_endpoint": func(f *OpenidFederation, _ string) error {
			_, err := f.FetchIdpList()
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

func TestFederationDoesNotFollowARedirect(t *testing.T) {
	stub := newFederationStub(t)
	endpoints := map[string]any{"federation_fetch_endpoint": stub.URL + "/redirecting", "idp_list_endpoint": stub.URL + "/redirecting"}
	stub.masterStatement = signJWS(t, stub.masterKey, "master", map[string]any{"iss": stub.URL, "sub": stub.URL, "metadata": map[string]any{"federation_entity": endpoints}})
	federation := stub.federation(t)
	if _, err := federation.FetchIdpList(); err == nil {
		t.Error("list accepted")
	}
	if _, err := federation.FetchEntityStatement(stub.URL + "/op"); err == nil {
		t.Error("statement accepted")
	}
	if n := stub.redirected.Load(); n != 0 {
		t.Errorf("%d requests followed a redirect", n)
	}
}

func TestFetchSignedJwksTakesAnHTTPSURIOnly(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op := &EntityStatement{
		Jwks:     &Jwks{Keys: keySetOf(stub.opKey, "op")},
		Metadata: &Metadata{OpenidProvider: &OpenIDProviderMetadata{SignedJwksURI: "http" + strings.TrimPrefix(stub.URL, "https") + "/op/jwks"}},
	}
	if _, err := federation.FetchSignedJwks(op); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v", err)
	}
}

func TestFetchSignedJwksDoesNotFollowARedirect(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op := &EntityStatement{
		Jwks:     &Jwks{Keys: keySetOf(stub.opKey, "op")},
		Metadata: &Metadata{OpenidProvider: &OpenIDProviderMetadata{SignedJwksURI: stub.URL + "/redirecting"}},
	}
	if _, err := federation.FetchSignedJwks(op); err == nil {
		t.Error("accepted")
	}
	if n := stub.redirected.Load(); n != 0 {
		t.Errorf("%d requests followed a redirect", n)
	}
}

func TestFetchSignedJwksRefusesAnOldSetOrOneThatNeverExpires(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op, err := federation.FetchEntityStatement(stub.URL + "/op")
	if err != nil {
		t.Fatal(err)
	}
	keys := keySetOf(stub.jwksKey, "idtoken").Keys
	for name, claims := range map[string]map[string]any{
		"expired":       {"keys": keys, "exp": time.Now().Add(-time.Hour).Unix()},
		"expires soon":  {"keys": keys, "exp": time.Now().Add(statementClockTolerance / 2).Unix()},
		"never expires": {"keys": keys},
		"not yet valid": {"keys": keys, "exp": time.Now().Add(2 * time.Hour).Unix(), "nbf": time.Now().Add(time.Hour).Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			stub.signedJwks = signJWS(t, stub.opKey, "op", claims)
			if _, err := federation.FetchSignedJwks(op); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestFederationReadsNoMoreThanItsBound(t *testing.T) {
	stub := newFederationStub(t)
	federation := stub.federation(t)
	op, err := federation.FetchEntityStatement(stub.URL + "/op")
	if err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat(" ", maxFederationResponseBytes) + stub.signedJwks
	stub.signedJwks, stub.idpList, stub.fetchStatement = huge, huge, huge
	for name, fetch := range map[string]func() error{
		"signed JWKS": func() error { _, err := federation.FetchSignedJwks(op); return err },
		"IdP list":    func() error { _, err := federation.FetchIdpList(); return err },
		"statement":   func() error { _, err := federation.FetchEntityStatement(stub.URL + "/op"); return err },
	} {
		if err := fetch(); err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRelyingPartyTakesAProviderWhoseEndpointsAreAllHTTPS(t *testing.T) {
	stub := newFederationStub(t)
	if _, err := stub.relyingParty(t).newClient(stub.URL + "/op"); err != nil {
		t.Fatal(err)
	}
}

func TestRelyingPartyRefusesAProviderWithAnEndpointThatIsNotHTTPS(t *testing.T) {
	for _, endpoint := range []string{"authorization_endpoint", "pushed_authorization_request_endpoint", "token_endpoint"} {
		t.Run(endpoint, func(t *testing.T) {
			stub := newFederationStub(t)
			stub.opStatement = signJWS(t, stub.opKey, "op", stub.opClaims(map[string]any{endpoint: "http://op.example/plain"}))
			if _, err := stub.relyingParty(t).newClient(stub.URL + "/op"); err == nil || !strings.Contains(err.Error(), endpoint) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// The relying party's client carries its mTLS key, which a redirect would present elsewhere.
func TestRelyingPartyDoesNotFollowARedirectFromPARNorTheTokenEndpoint(t *testing.T) {
	cfg := testRelyingPartyConfig(t, newFederationStub(t))
	rp, err := NewRelyingParty(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if rp.httpClient.CheckRedirect == nil || rp.httpClient.CheckRedirect(nil, nil) == nil {
		t.Error("the mTLS client follows redirects")
	}
}

func TestServeSignedJwksAnswersOnlyOnceWhenItCannotSign(t *testing.T) {
	rp := &RelyingParty{
		sigPrivateKey:   "not a key",
		entityStatement: &EntityStatement{Metadata: &Metadata{OpenidRelyingParty: &OpenIDRelyingPartyMetadata{Jwks: &Jwks{Keys: &jose.JSONWebKeySet{}}}}},
	}
	recorder := httptest.NewRecorder()
	rp.ServeSignedJwks(recorder, httptest.NewRequest(http.MethodGet, "/jwks", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d", recorder.Code)
	}
	if strings.Contains(recorder.Header().Get("Content-Type"), "jwt") {
		t.Errorf("content type = %s", recorder.Header().Get("Content-Type"))
	}
}

func TestLoadCertBytesFromPemNamesTheFileWithoutAMissingError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, []byte("no pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadCertBytesFromPem(path)
	if err == nil || strings.Contains(err.Error(), "%!") || !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v", err)
	}
}

// Server rules 5 and 14. A provider's refusal may echo what it was sent, and the statement fetch's failure body comes
// from outside.
func TestAFederatedLoginLogsNoSecretAtDebug(t *testing.T) {
	const (
		state, nonce, verifier = "state-value", "nonce-value", "verifier-value"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "id_token": stub.idToken})
		}
	}))
	defer server.Close()
	stub.client.rp.httpClient = server.Client()
	stub.client.op.Metadata.OpenidProvider.TokenEndpoint = server.URL + "/token"
	stub.client.op.Metadata.OpenidProvider.PushedAuthorizationRequestEndpoint = server.URL + "/par"
	claims := validIDTokenClaims()
	claims["nonce"] = nonce
	stub.idToken = stub.nestedToken(t, claims)

	login := oidc.Login{State: state, Nonce: nonce, Verifier: verifier}
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
	if _, err := NewOpenidFederation(failing.URL, keySetOf(newTestKey(t), "master"), WithHTTPClient(failing.Client())); err == nil {
		t.Fatal("the failure went unnoticed")
	}

	for _, value := range []string{state, nonce, verifier, code, requestURI, token, stub.idToken} {
		if strings.Contains(logs.String(), value) {
			t.Errorf("the log holds %q:\n%s", value, logs.String())
		}
	}
}

// testRelyingPartyConfig is a relying party of the stub's federation, with keys in a temporary directory.
func testRelyingPartyConfig(t *testing.T, stub *federationStub) *RelyingPartyConfig {
	t.Helper()
	dir := t.TempDir()
	keyPath := func(name string) string {
		der, err := x509.MarshalPKCS8PrivateKey(newTestKey(t))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	clientKey := keyPath("client.pem")
	certPath, err := generateCert(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(certPath) })
	master := &Jwk{Key: &keySetOf(stub.masterKey, "master").Keys[0]}
	return &RelyingPartyConfig{
		Subject:      "https://rp.example",
		FedMasterURL: stub.URL,
		FedMasterJWK: master,
		SignKey:      KeyConfig{KeyPEMPath: keyPath("sign.pem")},
		EncKey:       KeyConfig{KeyPEMPath: keyPath("enc.pem")},
		ClientKey:    KeyConfig{KeyPEMPath: clientKey, CertPEMPath: certPath},
		RelyingParty: RelyingPartyMetadata{ClientName: "rp", RedirectURIs: []string{"https://rp.example/cb"}},
		HTTPClient:   stub.Client(),
	}
}

// OIDC Core 3.1.3.7, step 11: a token issued for another login must not be accepted for this one.
func TestExchangeRefusesAnIDTokenOfAnotherLogin(t *testing.T) {
	stub := newLoginStub(t)
	stub.idToken = stub.nestedToken(t, validIDTokenClaims())
	if _, err := stub.client.Exchange(t.Context(), oidc.Login{Nonce: "another", Verifier: "verifier"}, "code"); !errors.Is(err, oidc.ErrNonceMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func withoutAlg(set *jose.JSONWebKeySet) *jose.JSONWebKeySet {
	set.Keys[0].Algorithm = ""
	return set
}

// T-Systems' IdPs in the reference federation publish every key without alg, which RFC 7517 section 4.4 leaves optional.
func TestFederationAcceptsMemberKeysWithoutAlg(t *testing.T) {
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
	op, err := federation.FetchEntityStatement(stub.URL + "/op")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := federation.FetchSignedJwks(op); err != nil {
		t.Fatal(err)
	}
}

// Without an alg on the key, its type and curve still leave the token one algorithm.
func TestFederationRefusesMemberTokenWhoseAlgDoesNotFitTheKeyWithoutAlg(t *testing.T) {
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
	if _, err := stub.federation(t).FetchEntityStatement(stub.URL + "/op"); err == nil || !strings.Contains(err.Error(), "cannot verify ES384") {
		t.Errorf("not refused for its algorithm: %v", err)
	}
}

func TestExchangeVerifiesAnIDTokenWithAKeyWithoutAlg(t *testing.T) {
	stub := newLoginStub(t)
	withoutAlg(stub.client.jwks)
	stub.idToken = stub.nestedToken(t, validIDTokenClaims())
	if _, err := stub.client.Exchange(t.Context(), oidc.Login{Nonce: "n", Verifier: "verifier"}, "code"); err != nil {
		t.Fatal(err)
	}
}
