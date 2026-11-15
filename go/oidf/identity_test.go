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
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
)

// federatedLogin is a relying party of the federation stub with a client of its provider, and the keys the provider
// encrypts and signs ID tokens with.
type federatedLogin struct {
	stub    *federationStub
	rp      *RelyingParty
	client  *RelyingPartyClient
	encKey  *ecdsa.PrivateKey
	fetches *fetchCounter
	now     atomic.Pointer[time.Time]
}

func newFederatedLogin(t *testing.T) *federatedLogin {
	t.Helper()
	login := &federatedLogin{stub: newFederationStub(t), encKey: newTestKey(t)}
	login.rp = login.stub.relyingParty(t)
	login.rp.keys = Keys{Decrypt: ecdhKey(t, login.encKey), DecryptKID: "enc"}
	metadata := login.rp.entityStatement.Metadata.OpenidRelyingParty
	metadata.Scope = defaultMetadataScope
	metadata.TIFeaturesSupported = &TIFeatures{IDTokenVersionSupported: []string{"1.0.0", "2.0.0"}}
	login.rp.cfg.Clock = func() time.Time {
		if now := login.now.Load(); now != nil {
			return *now
		}
		return time.Now()
	}
	client, err := login.rp.Client(t.Context(), login.stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	login.client = client
	login.fetches = login.stub.countFetches()
	return login
}

func (l *federatedLogin) claims() map[string]any {
	claims := validIDTokenClaims()
	claims["iss"] = l.stub.URL + "/op"
	return claims
}

// issue makes the provider answer with an ID token signed by key under kid and encrypted with the JWE header members
// given.
func (l *federatedLogin) issue(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any, header map[string]any) {
	t.Helper()
	options := &jose.EncrypterOptions{}
	for name, value := range header {
		options = options.WithHeader(jose.HeaderKey(name), value)
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: l.encKey.Public(), KeyID: "enc"}, options)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encrypter.Encrypt([]byte(signJWS(t, key, kid, claims)))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := encrypted.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	l.stub.idToken.Store(&compact)
}

func (l *federatedLogin) exchange(t *testing.T, login openid.Login) (*Identity, error) {
	t.Helper()
	identity, _, err := l.client.ExchangeIdentity(t.Context(), login, "code")
	return identity, err
}

func nLogin() openid.Login {
	return openid.Login{Nonce: "n", Verifier: testVerifier}
}

// refetches counts the fetches of the provider's documents past what the client had.
func (l *federatedLogin) refetches() int {
	return l.fetches.count("/op/jwks")
}

// OIDC Core 3.1.2.1 and gemSpec_IDP_FD A_28484: the acr is a gematik level of assurance no lower than the lowest the
// login asked for, high when it asked for none.
func TestOIDCCore_3_1_2_1_ALowerACRThanAskedIsRefused(t *testing.T) {
	for _, c := range []struct {
		asked []string
		acr   any
		ok    bool
	}{
		{nil, LoAHigh, true},
		{nil, LoASubstantial, false},
		{[]string{LoAHigh}, LoASubstantial, false},
		{[]string{LoAHigh, LoASubstantial}, LoASubstantial, true},
		{[]string{LoASubstantial}, LoAHigh, true},
		{[]string{LoASubstantial}, LoALow, false},
		{[]string{LoALow}, LoALow, true},
		{nil, "urn:example:loa", false},
		{nil, "GEMATIK-EHEALTH-LOA-HIGH", false},
		{nil, nil, false},
		{nil, 3, false},
	} {
		stub := newLoginStub(t)
		claims := validIDTokenClaims()
		if c.acr == nil {
			delete(claims, "acr")
		} else {
			claims["acr"] = c.acr
		}
		stub.idToken = stub.nestedToken(t, claims)
		login := openid.Login{Nonce: "n", Verifier: testVerifier, ACRValues: c.asked}
		_, _, err := stub.client.ExchangeIdentity(t.Context(), login, "code")
		if c.ok && err != nil || !c.ok && !errors.Is(err, ErrACR) {
			t.Errorf("asked %v, acr %v: %v", c.asked, c.acr, err)
		}
	}
}

// gemSpec_IDP_FD A_28484: a login may ask for a lower level now that the acr is judged, and only for a gematik level.
func TestA_28484_ALoginAsksForGematikLevelsOnly(t *testing.T) {
	stub := newLoginStub(t)
	pushed, form := stub.withPAR(t)
	login := validLogin()
	login.ACRValues = []string{"urn:example:loa"}
	if _, err := stub.client.AuthenticationURL(t.Context(), login); !errors.Is(err, ErrACRValues) {
		t.Fatalf("err = %v", err)
	}
	if pushed.Load() != 0 {
		t.Fatal("the request reached the IDP")
	}
	login.ACRValues = []string{LoAHigh, LoASubstantial}
	if _, err := stub.client.AuthenticationURL(t.Context(), login); err != nil {
		t.Fatal(err)
	}
	if got := form.Load().Get("acr_values"); got != LoAHigh+" "+LoASubstantial {
		t.Errorf("acr_values = %q", got)
	}
	login.ACRValues = nil
	if _, err := stub.client.AuthenticationURL(t.Context(), login); err != nil {
		t.Fatal(err)
	}
	if got := form.Load().Get("acr_values"); got != LoAHigh {
		t.Errorf("default acr_values = %q", got)
	}
}

// gemSpec_IDP_FD A_28484, gemSpec_IDP_Sek A_23129-06: amr names how the person authenticated, a JSON array of methods.
func TestA_28484_TheAMRIsAListOfMethods(t *testing.T) {
	for name, amr := range map[string]any{
		"missing":       nil,
		"empty":         []string{},
		"a string":      "urn:telematik:auth:eGK",
		"a number in":   []any{"urn:telematik:auth:eGK", 1},
		"an empty one":  []string{""},
		"a CR in one":   []string{"urn:telematik:auth:eGK\r"},
		"seventeen":     strings.Split(strings.Repeat("m,", 16)+"m", ","),
		"a null within": []any{nil},
	} {
		stub := newLoginStub(t)
		claims := validIDTokenClaims()
		if amr == nil {
			delete(claims, "amr")
		} else {
			claims["amr"] = amr
		}
		stub.idToken = stub.nestedToken(t, claims)
		if _, _, err := stub.client.ExchangeIdentity(t.Context(), nLogin(), "code"); !errors.Is(err, ErrAMR) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// OIDC Core 2 and 5.5: auth_time is required when the login asks for it in its claims request; when present it is a
// NumericDate no further ahead of the clock than the skew.
func TestOIDCCore_2_AnAuthTimeThatIsAskedForOrPresentIsChecked(t *testing.T) {
	askedFor := json.RawMessage(`{"id_token":{"auth_time":null}}`)
	for name, c := range map[string]struct {
		authTime any
		claims   json.RawMessage
		reason   string
	}{
		"missing, asked for":    {nil, askedFor, "missing although asked for"},
		"a string":              {"1700000000", nil, "no number"},
		"null":                  {json.RawMessage("null"), nil, "no number"},
		"an object":             {map[string]any{}, nil, "no number"},
		"ahead":                 {time.Now().Add(2 * time.Minute).Unix(), nil, "ahead of the clock"},
		"a fraction ahead":      {float64(time.Now().Add(90*time.Second).UnixMilli()) / 1000, nil, "ahead of the clock"},
		"past year 9999":        {1e15, nil, "out of range"},
		"negative":              {-1, nil, "out of range"},
		"missing, not asked":    {nil, nil, ""},
		"within the skew ahead": {time.Now().Add(30 * time.Second).Unix(), askedFor, ""},
	} {
		stub := newLoginStub(t)
		claims := validIDTokenClaims()
		if c.authTime == nil {
			delete(claims, "auth_time")
		} else {
			claims["auth_time"] = c.authTime
		}
		stub.idToken = stub.nestedToken(t, claims)
		login := nLogin()
		login.Claims = c.claims
		_, _, err := stub.client.ExchangeIdentity(t.Context(), login, "code")
		if c.reason == "" && err != nil || c.reason != "" && (!errors.Is(err, ErrAuthTime) || !strings.HasSuffix(err.Error(), c.reason)) {
			t.Errorf("%s: %v, want %q", name, err, c.reason)
		}
	}
}

// OIDC Core 3.1.3.7: iat is required, and with several audiences azp names this client; an azp always does.
func TestOIDCCore_3_1_3_7_IatAndAzpAreChecked(t *testing.T) {
	for name, c := range map[string]struct {
		change func(map[string]any)
		want   error
	}{
		"no iat":                        {func(c map[string]any) { delete(c, "iat") }, openid.ErrMissingClaim},
		"several audiences without azp": {func(c map[string]any) { c["aud"] = []string{"https://rp.example", "https://other.example"} }, ErrAuthorizedParty},
		"azp of another client":         {func(c map[string]any) { c["azp"] = "https://other.example" }, ErrAuthorizedParty},
		"azp no text":                   {func(c map[string]any) { c["azp"] = 1 }, ErrAuthorizedParty},
		"iat ahead beyond the skew":     {func(c map[string]any) { c["iat"] = time.Now().Add(2 * time.Minute).Unix() }, openid.ErrTokenIssuedInFuture},
		"several audiences with azp": {func(c map[string]any) {
			c["aud"], c["azp"] = []string{"https://rp.example", "https://other.example"}, "https://rp.example"
		}, nil},
		"iat ahead within the skew": {func(c map[string]any) { c["iat"] = time.Now().Add(30 * time.Second).Unix() }, nil},
	} {
		stub := newLoginStub(t)
		claims := validIDTokenClaims()
		c.change(claims)
		stub.idToken = stub.nestedToken(t, claims)
		_, _, err := stub.client.ExchangeIdentity(t.Context(), nLogin(), "code")
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// gemSpec_IDP_Sek A_27591 and A_27592: the signals of version 2.0.0 are read as text or a list of text, and nothing
// else; consent does not lower the level a login takes.
func TestA_27591_ConsentAndInteractiveAreReadStrictly(t *testing.T) {
	for name, c := range map[string]struct {
		consent, interactive any
		acr                  string
		asked                []string
		want                 error
	}{
		"consent as text":           {"loa-substantial", nil, LoASubstantial, []string{LoAHigh, LoASubstantial}, nil},
		"consent as a list":         {[]string{"loa-substantial"}, "silent", LoASubstantial, []string{LoAHigh, LoASubstantial}, nil},
		"consent, only high asked":  {[]string{"loa-substantial"}, nil, LoASubstantial, nil, ErrACR},
		"consent a number":          {1, nil, LoAHigh, nil, ErrIdentityClaim},
		"consent with a CR":         {"loa\r", nil, LoAHigh, nil, ErrIdentityClaim},
		"consent of 17":             {strings.Split(strings.Repeat("c,", 16)+"c", ","), nil, LoAHigh, nil, ErrIdentityClaim},
		"interactive a list of two": {nil, []string{"silent", "x"}, LoAHigh, nil, ErrIdentityClaim},
		"interactive an object":     {nil, map[string]any{}, LoAHigh, nil, ErrIdentityClaim},
	} {
		stub := newLoginStub(t)
		claims := validIDTokenClaims()
		claims["acr"] = c.acr
		if c.consent != nil {
			claims[claimConsent] = c.consent
		}
		if c.interactive != nil {
			claims[claimInteractive] = c.interactive
		}
		stub.idToken = stub.nestedToken(t, claims)
		login := nLogin()
		login.ACRValues = c.asked
		identity, _, err := stub.client.ExchangeIdentity(t.Context(), login, "code")
		if c.want != nil {
			if !errors.Is(err, c.want) {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err != nil || len(identity.Consent) != 1 || identity.Consent[0] != "loa-substantial" {
			t.Errorf("%s: %+v, %v", name, identity, err)
		}
	}
}

// gemSpec_IDP_Sek A_22989-02 Tabelle 6: the identity carries the claims the IDP sends, the level of assurance and the
// methods, and the version of the token.
func TestIDPSek_TheIdentityCarriesACRAndAMR(t *testing.T) {
	stub := newLoginStub(t)
	claims := validIDTokenClaims()
	claims["acr"] = LoASubstantial
	claims["amr"] = []string{"urn:telematik:auth:other", "urn:telematik:auth:mEW"}
	claims[claimID] = "X123456789"
	claims[claimDisplayName] = "Erika Mustermann"
	claims[claimGivenName] = "Erika"
	claims[claimFamilyName] = "Mustermann"
	claims[claimProfession] = "1.2.276.0.76.4.49"
	claims[claimOrganization] = "109500969"
	claims[claimBirthdate] = "1964-08-12"
	stub.idToken = stub.nestedToken(t, claims)
	login := nLogin()
	login.ACRValues = []string{LoAHigh, LoASubstantial}
	identity, response, err := stub.client.ExchangeIdentity(t.Context(), login, "code")
	if err != nil {
		t.Fatal(err)
	}
	want := Identity{
		Issuer: "https://op.example", Profession: "1.2.276.0.76.4.49", Organization: "109500969",
		ACR: LoASubstantial, IDTokenVersion: "1.0.0",
		Personal: Personal{
			Subject: "subject", ID: "X123456789", DisplayName: "Erika Mustermann", GivenName: "Erika",
			FamilyName: "Mustermann", Birthdate: "1964-08-12",
		},
	}
	got := *identity
	if got.AuthTime.Unix() != claims["auth_time"] || len(got.AMR) != 2 || got.AMR[1] != "urn:telematik:auth:mEW" || strings.Join(got.Scopes, " ") != strings.Join(defaultOPScopes, " ") {
		t.Errorf("auth_time %v, amr %v, scopes %v", got.AuthTime, got.AMR, got.Scopes)
	}
	got.AuthTime, got.AMR, got.Scopes = time.Time{}, nil, nil
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		t.Errorf("identity = %s, want %s", gotJSON, wantJSON)
	}
	if strings.Count(response.IDTokenRaw, ".") != 2 {
		t.Error("the response does not carry the inner JWS")
	}
}

// RFC 6749 section 5.1: the scopes granted are the response's scope, the ones asked for when it names none.
func TestRFC6749_5_1_TheIdentityCarriesTheScopesGranted(t *testing.T) {
	for scope, want := range map[string]string{
		"":                                  "openid urn:telematik:display_name",
		"openid urn:telematik:versicherter": "openid urn:telematik:versicherter",
	} {
		stub := newLoginStub(t)
		stub.idToken = stub.nestedToken(t, validIDTokenClaims())
		stub.scope = scope
		login := nLogin()
		login.Scopes = []string{"openid", "urn:telematik:display_name"}
		identity, _, err := stub.client.ExchangeIdentity(t.Context(), login, "code")
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(identity.Scopes, " "); got != want {
			t.Errorf("scope %q: scopes %q", scope, got)
		}
	}
	for _, scope := range []string{"openid  x", "openid\tx", "a\"b", " openid"} {
		stub := newLoginStub(t)
		stub.idToken = stub.nestedToken(t, validIDTokenClaims())
		stub.scope = scope
		if _, _, err := stub.client.ExchangeIdentity(t.Context(), nLogin(), "code"); !errors.Is(err, openid.ErrTokenResponse) {
			t.Errorf("scope %q: %v", scope, err)
		}
	}
}

// gemSpec_IDP_FD A_22860-02: a claim the login asked for as essential has to be in the ID token.
func TestA_22860_02_AnEssentialClaimMissingIsRefused(t *testing.T) {
	stub := newLoginStub(t)
	stub.idToken = stub.nestedToken(t, validIDTokenClaims())
	login := nLogin()
	login.Claims = json.RawMessage(`{"id_token":{"urn:telematik:claims:id":{"essential":true}}}`)
	if _, _, err := stub.client.ExchangeIdentity(t.Context(), login, "code"); !errors.Is(err, ErrEssentialClaim) {
		t.Fatalf("err = %v", err)
	}
	login.Claims = json.RawMessage(`{"id_token":{"urn:telematik:claims:id":null,"urn:telematik:claims:email":{"essential":false}},"userinfo":{"x":{"essential":true}}}`)
	if _, _, err := stub.client.ExchangeIdentity(t.Context(), login, "code"); err != nil {
		t.Fatalf("not essential: %v", err)
	}
	claims := validIDTokenClaims()
	claims[claimID] = "X123456789"
	stub.idToken = stub.nestedToken(t, claims)
	login.Claims = json.RawMessage(`{"id_token":{"urn:telematik:claims:id":{"essential":true}}}`)
	if _, _, err := stub.client.ExchangeIdentity(t.Context(), login, "code"); err != nil {
		t.Fatalf("present: %v", err)
	}
}

// gemSpec_IDP_FD A_22861: a kid the IDP's signed JWKS does not name refetches the IDP's statement and signed JWKS
// once, past the store, and a rotated key verifies.
func TestA_22861_AnUnknownKIDRefetchesOnce(t *testing.T) {
	login := newFederatedLogin(t)
	rotated := newTestKey(t)
	login.stub.signedJwks = signJWS(t, login.stub.opKey, "op", map[string]any{
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "keys": keySetOf(rotated, "rotated").Keys,
	})
	login.issue(t, rotated, "rotated", login.claims(), nil)
	if _, err := login.exchange(t, nLogin()); err != nil {
		t.Fatal(err)
	}
	if n := login.refetches(); n != 1 {
		t.Fatalf("%d refetches", n)
	}
	// A later client reads what the refetch kept.
	client, err := login.rp.Client(t.Context(), login.stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	if len(client.provider().jwks.Key("rotated")) != 1 || login.refetches() != 1 {
		t.Errorf("the refetched JWKS was not kept: %d fetches", login.refetches())
	}

	// Another unknown kid within the minute: refused without a fetch.
	login.issue(t, newTestKey(t), "made-up", login.claims(), nil)
	if _, err := login.exchange(t, nLogin()); !errors.Is(err, ErrIDTokenKey) {
		t.Fatalf("err = %v", err)
	}
	if n := login.refetches(); n != 1 {
		t.Fatalf("%d refetches within the minute", n)
	}
	later := time.Now().Add(refetchInterval + time.Second)
	login.now.Store(&later)
	if _, err := login.exchange(t, nLogin()); !errors.Is(err, ErrIDTokenKey) {
		t.Fatalf("err = %v", err)
	}
	if n := login.refetches(); n != 2 {
		t.Fatalf("%d refetches after the minute", n)
	}
}

// rotate makes the provider publish a new ID token key and returns it; the store still holds the old JWKS.
func (l *federatedLogin) rotate(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	rotated := newTestKey(t)
	l.stub.signedJwks = signJWS(t, l.stub.opKey, "op", map[string]any{
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "keys": keySetOf(rotated, "rotated").Keys,
	})
	return rotated
}

// gate holds every request for path until release is called; entered receives one value per request held.
func (s *federationStub) gate(path string) (entered <-chan struct{}, release func()) {
	arrived, open := make(chan struct{}, 16), make(chan struct{})
	handler := s.Config.Handler
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			arrived <- struct{}{}
			<-open
		}
		handler.ServeHTTP(w, r)
	})
	var once sync.Once
	return arrived, func() { once.Do(func() { close(open) }) }
}

// overlap starts the exchanges of first and second so that second meets the new kid while the refetch first started
// is held at the provider's JWKS: it returns once second waits for that refetch, and fails the test if second fetches
// itself or gives up instead.
func (l *federatedLogin) overlap(firstCtx context.Context, t *testing.T, first, second *RelyingPartyClient) (firstErr, secondErr <-chan error, release func()) {
	t.Helper()
	entered, release := l.stub.gate("/op/jwks")
	t.Cleanup(release)
	waiting := make(chan struct{}, 1)
	l.rp.waitingForRefetch = func() { waiting <- struct{}{} }
	exchange := func(ctx context.Context, client *RelyingPartyClient) <-chan error {
		result := make(chan error, 1)
		go func() {
			_, _, err := client.ExchangeIdentity(ctx, nLogin(), "code")
			result <- err
		}()
		return result
	}
	firstErr = exchange(firstCtx, first)
	<-entered
	secondErr = exchange(t.Context(), second)
	select {
	case <-waiting:
	case <-entered:
		t.Fatal("the second exchange fetched the JWKS itself")
	case err := <-secondErr:
		t.Fatalf("the second exchange did not wait for the refetch: %v", err)
	}
	return firstErr, secondErr, release
}

// gemSpec_IDP_FD A_22861 during a key rotation: concurrent logins that meet the new kid wait for the one refetch in
// flight, and both succeed. The refetch is held until the second login waits for it, so the two overlap.
func TestA_22861_ConcurrentLoginsDuringARotationRefetchOnce(t *testing.T) {
	login := newFederatedLogin(t)
	login.issue(t, login.rotate(t), "rotated", login.claims(), nil)
	other, err := login.rp.Client(t.Context(), login.stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	firstErr, secondErr, release := login.overlap(t.Context(), t, login.client, other)
	release()
	for _, result := range []<-chan error{firstErr, secondErr} {
		if err := <-result; err != nil {
			t.Error(err)
		}
	}
	if n := login.refetches(); n != 1 {
		t.Errorf("%d refetches", n)
	}
}

// inMemory carries a client's requests to the federation stub's handler inside the test, so that a synctest bubble
// holds everything that waits; through serve, a test can hold or fail a request.
type inMemory struct {
	handler http.Handler
	serve   func(w http.ResponseWriter, r *http.Request, next http.Handler)
}

func (m inMemory) RoundTrip(r *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	m.serve(recorder, r, m.handler)
	return recorder.Result(), nil
}

// inBubble prepares a login for a synctest bubble: the clocks stand at now, taken outside the bubble when the
// documents were signed, as the bubble's clock starts in 2000, and the relying party's requests go through serve.
func (l *federatedLogin) inBubble(now time.Time, serve func(w http.ResponseWriter, r *http.Request, next http.Handler)) {
	l.now.Store(&now)
	l.rp.federation.clock = func() time.Time { return now }
	transport := inMemory{handler: l.stub.Config.Handler, serve: serve}
	l.rp.httpClient = &http.Client{Transport: transport}
	l.rp.federation.httpClient = &http.Client{Transport: transport, CheckRedirect: refuseRedirect}
}

// gemSpec_IDP_FD A_22861 asks for one refetch: with the federation failing, the logins of a minute that meet an
// unknown kid ask it once, and the store serves them meanwhile.
func TestA_22861_AFailingFederationIsAskedOnceAMinute(t *testing.T) {
	login := newFederatedLogin(t)
	login.issue(t, login.rotate(t), "rotated", login.claims(), nil)
	now := time.Now()
	synctest.Test(t, func(t *testing.T) {
		var federationRequests atomic.Int64
		login.inBubble(now, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet {
				federationRequests.Add(1)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			next.ServeHTTP(w, r)
		})
		for range 5 {
			if _, err := login.exchange(t, nLogin()); !errors.Is(err, ErrIDTokenKey) {
				t.Fatalf("err = %v", err)
			}
		}
		if n := federationRequests.Load(); n != 1 {
			t.Errorf("%d requests to the federation for 5 logins in the minute", n)
		}
	})
}

// gemSpec_IDP_FD A_22861: the refetch serves every login waiting for it, so the login that started it returns as
// soon as it hangs up, while the refetch goes on for the others, and a later login takes what it kept.
func TestA_22861_TheRefetchOutlivesTheLoginThatStartedIt(t *testing.T) {
	login := newFederatedLogin(t)
	login.issue(t, login.rotate(t), "rotated", login.claims(), nil)
	other, err := login.rp.Client(t.Context(), login.stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	synctest.Test(t, func(t *testing.T) {
		held := make(chan struct{})
		login.inBubble(now, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Path == "/op/jwks" {
				<-held
			}
			next.ServeHTTP(w, r)
		})
		exchange := func(ctx context.Context, client *RelyingPartyClient) <-chan error {
			result := make(chan error, 1)
			go func() {
				_, _, err := client.ExchangeIdentity(ctx, nLogin(), "code")
				result <- err
			}()
			return result
		}
		leaderCtx, cancel := context.WithCancel(t.Context())
		leader := exchange(leaderCtx, login.client)
		synctest.Wait()
		waiter := exchange(t.Context(), other)
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case err := <-leader:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("the login that hung up: %v", err)
			}
		default:
			t.Fatal("the login that hung up still waits for the refetch")
		}
		close(held)
		if err := <-waiter; err != nil {
			t.Fatalf("the waiting login: %v", err)
		}
		if _, err := login.exchange(t, nLogin()); err != nil {
			t.Fatalf("a later login: %v", err)
		}
		if n := login.refetches(); n != 1 {
			t.Errorf("%d refetches", n)
		}
	})
}

// gemSpec_IDP_FD A_22861: a client resolved before a refetch, meeting the new kid within the minute after it, takes
// the documents the refetch kept, without a fetch.
func TestA_22861_ALoginWithinTheMinuteAfterARefetchSucceedsFromTheStore(t *testing.T) {
	login := newFederatedLogin(t)
	stale, err := login.rp.Client(t.Context(), login.stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	login.issue(t, login.rotate(t), "rotated", login.claims(), nil)
	if _, err := login.exchange(t, nLogin()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stale.ExchangeIdentity(t.Context(), nLogin(), "code"); err != nil {
		t.Fatalf("the stale client: %v", err)
	}
	if n := login.refetches(); n != 1 {
		t.Errorf("%d refetches", n)
	}
}

// gemSpec_IDP_FD A_22861 speaks of an unknown key: a signature that does not verify under a known kid is refused and
// refetches nothing.
func TestA_22861_AnUnknownKIDRefetchesOnce_ABrokenSignatureDoesNot(t *testing.T) {
	login := newFederatedLogin(t)
	login.issue(t, newTestKey(t), "idtoken", login.claims(), nil)
	if _, err := login.exchange(t, nLogin()); err == nil || errors.Is(err, ErrIDTokenKey) {
		t.Fatalf("err = %v", err)
	}
	if n := login.refetches(); n != 0 {
		t.Fatalf("%d refetches", n)
	}
	login.issue(t, login.stub.jwksKey, "idtoken", login.claims(), nil)
	if _, err := login.exchange(t, nLogin()); err != nil {
		t.Fatal(err)
	}
}

// gemSpec_IDP_FD A_23207 Hinweis 3: a version the IDP's statement does not list may come from an outdated statement,
// which is refetched once.
func TestA_23207_AnUnlistedVersionRefetchesOnce(t *testing.T) {
	login := newFederatedLogin(t)
	claims := login.stub.opClaims(nil)
	claims["metadata"].(map[string]any)["openid_provider"].(map[string]any)["ti_features_supported"] = map[string]any{"id_token_version_supported": []string{"1.0.0", "2.0.0"}}
	login.stub.opStatement = signJWS(t, login.stub.opKey, "op", claims)
	login.issue(t, login.stub.jwksKey, "idtoken", login.claims(), map[string]any{"version": "2.0.0"})
	identity, err := login.exchange(t, nLogin())
	if err != nil {
		t.Fatal(err)
	}
	if identity.IDTokenVersion != "2.0.0" || login.refetches() != 1 {
		t.Errorf("version %q, %d refetches", identity.IDTokenVersion, login.refetches())
	}
}

// gemSpec_IDP_FD A_23207 Hinweis 3 and gemSpec_IDP_Sek A_27598: a version still unlisted after the refetch, one the
// relying party does not publish, or one A_27505 does not know is refused.
func TestA_23207_AVersionNeitherSideListsIsRefused(t *testing.T) {
	login := newFederatedLogin(t)
	login.issue(t, login.stub.jwksKey, "idtoken", login.claims(), map[string]any{"version": "2.0.0"})
	if _, err := login.exchange(t, nLogin()); !errors.Is(err, ErrIDTokenVersion) {
		t.Fatalf("unlisted: %v", err)
	}
	if n := login.refetches(); n != 1 {
		t.Fatalf("%d refetches", n)
	}
	login.rp.entityStatement.Metadata.OpenidRelyingParty.TIFeaturesSupported = nil
	for _, version := range []any{"2.0.0", "3.0.0", 2} {
		login.issue(t, login.stub.jwksKey, "idtoken", login.claims(), map[string]any{"version": version})
		if _, err := login.exchange(t, nLogin()); !errors.Is(err, ErrIDTokenVersion) {
			t.Errorf("%v: %v", version, err)
		}
	}
	if n := login.refetches(); n != 1 {
		t.Fatalf("%d refetches", n)
	}
}

// hostSession is how a host might hold an identity in its own exported struct.
type hostSession struct {
	ID       string
	Identity Identity
	Person   *Personal
}

// Servers rule 14: the personal claims of an identity never reach a log or an error by formatting, also inside a
// host's struct, a map or a slice, while what tells how and where the person logged in does.
func TestServerRule14_AnIdentityDoesNotLogItsPersonalClaims(t *testing.T) {
	identity := &Identity{
		Issuer: "https://idp.example", Profession: "1.2.276.0.76.4.49", Organization: "109500969", ACR: LoASubstantial,
		AMR: []string{"urn:telematik:auth:eGK"}, AuthTime: time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC), IDTokenVersion: "2.0.0",
		Consent: []string{"loa-substantial"}, Interactive: "silent", Scopes: []string{"openid", "urn:telematik:versicherter"},
		Personal: Personal{
			Subject: "subject-7f3a", ID: "X110411675", DisplayName: "Erika Mustermann-Display", GivenName: "ErikaGiven",
			FamilyName: "MustermannFamily", Birthdate: "1964-08-12",
		},
	}
	p := identity.Personal
	personal := []string{p.Subject, p.ID, p.DisplayName, p.GivenName, p.FamilyName, p.Birthdate}
	shown := []string{identity.Issuer, identity.Profession, identity.Organization, identity.ACR, identity.AMR[0], "2026-11-15T08:00:00Z", identity.IDTokenVersion, "loa-substantial", "silent", "urn:telematik:versicherter"}

	session := hostSession{ID: "session-1", Identity: *identity, Person: &identity.Personal}
	values := []any{
		identity, *identity, identity.Personal, &identity.Personal, session, &session,
		map[string]Identity{"a": *identity},
		[]Identity{*identity},
		[]Personal{identity.Personal},
	}
	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		for _, value := range values {
			outputs = append(outputs, fmt.Sprintf(verb, value))
		}
	}
	outputs = append(outputs, identity.String(), identity.Personal.String(), fmt.Errorf("login: %v", identity).Error(), fmt.Errorf("login: %+v", session).Error())
	var text, structured, hosted bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("login", "identity", identity, "personal", identity.Personal)
	slog.New(slog.NewJSONHandler(&structured, nil)).Info("login", "identity", *identity, "personal", identity.Personal)
	slog.New(slog.NewTextHandler(&hosted, nil)).Info("login", "session", session)
	outputs = append(outputs, text.String(), structured.String(), hosted.String())

	for _, output := range outputs {
		for _, value := range personal {
			if strings.Contains(output, value) {
				t.Errorf("%q shows %q", output, value)
			}
		}
		if !strings.Contains(output, "redacted") {
			t.Errorf("%q does not say what is withheld", output)
		}
	}
	for _, output := range []string{identity.String(), text.String(), structured.String(), hosted.String()} {
		for _, value := range shown {
			if !strings.Contains(output, value) {
				t.Errorf("%q lacks %q", output, value)
			}
		}
	}
	// json.Marshal is not redacted: the fields stay data a host can keep.
	stored, err := json.Marshal(identity)
	if err != nil || !bytes.Contains(stored, []byte(p.ID)) || !bytes.Contains(stored, []byte(p.Subject)) {
		t.Errorf("JSON %s, %v", stored, err)
	}
}

func FuzzIdentity(f *testing.F) {
	f.Add([]byte(`{"sub":"s","acr":"gematik-ehealth-loa-high","amr":["urn:telematik:auth:eGK"],"auth_time":1700000000,"iat":1700000000,"urn:telematik:claims:id":"X1","birthdate":"1964-08-12"}`))
	f.Add([]byte(`{"sub":"s","SUB":"t","acr":"x","amr":[],"auth_time":1e999}`))
	f.Add([]byte(`{"sub":"s\r\nX: y","acr":"gematik-ehealth-loa-high","amr":["a"],"auth_time":1}`))
	f.Add([]byte("{\"sub\":\"\xff\",\"acr\":\"gematik-ehealth-loa-high\",\"amr\":[\"a\"],\"auth_time\":1}"))
	f.Add([]byte(`{"sub":"s","acr":"gematik-ehealth-loa-high","amr":["a",null,1],"auth_time":-1,"urn:telematik:claims:display_name":{"x":1}}`))
	f.Add([]byte(`{"sub":"s","sub":"t","acr":"gematik-ehealth-loa-high","amr":["\u202e"],"auth_time":253402300799.9}`))
	f.Add([]byte(`{"sub":"s","acr":"gematik-ehealth-loa-substantial","amr":["a"],"iat":1,"aud":["x","y"],"azp":"x","urn:telematik:auth:consent":["loa-substantial"],"urn:telematik:auth:interactive":"silent"}`))
	login := openid.Login{Nonce: "n", Verifier: testVerifier, ACRValues: []string{LoAHigh, LoASubstantial}, Claims: json.RawMessage(`{"id_token":{"auth_time":{"essential":true}}}`)}
	f.Fuzz(func(t *testing.T, payload []byte) {
		identity, err := parseIdentity(payload, "https://op.example", "1.0.0")
		if err != nil {
			if len(payload) >= 16 && strings.Contains(err.Error(), string(payload)) {
				t.Fatalf("the error holds the input: %v", err)
			}
			return
		}
		texts := []string{
			identity.Personal.Subject, identity.Personal.ID, identity.Personal.DisplayName, identity.Personal.GivenName,
			identity.Personal.FamilyName, identity.Personal.Birthdate, identity.Profession, identity.Organization,
			identity.ACR, identity.Interactive,
		}
		texts = append(append(texts, identity.AMR...), identity.Consent...)
		// An oracle of the test's own: unicode.In over the categories, where checkText asks IsControl and In apart.
		refused := func(r rune) bool { return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) }
		for _, text := range texts {
			if !utf8.ValidString(text) || len(text) > maxTextBytes || strings.ContainsFunc(text, refused) {
				t.Fatalf("accepted %q", text)
			}
		}
		if identity.Personal.Subject == "" || len(identity.AMR) == 0 || len(identity.AMR) > maxAMREntries {
			t.Fatalf("accepted sub %q, amr %v", identity.Personal.Subject, identity.AMR)
		}
		if !identity.AuthTime.IsZero() && (identity.AuthTime.Unix() < 0 || identity.AuthTime.Unix() > maxNumericDate) {
			t.Fatalf("accepted auth_time %v", identity.AuthTime)
		}
		err = checkIdentity(identity, payload, login, "x", time.Unix(1700000000, 0))
		if err == nil && (identity.ACR != LoAHigh && identity.ACR != LoASubstantial || identity.AuthTime.IsZero()) {
			t.Fatalf("checkIdentity took acr %q, auth_time %v", identity.ACR, identity.AuthTime)
		}
	})
}

// A text a log or a reader would take for something else is refused: control characters, bidi overrides, zero-width
// characters and line separators. Internal invariant of checkText, which every text claim passes.
func TestServerRule14_TextWithControlOrFormatCharactersIsRefused(t *testing.T) {
	for _, r := range []rune{0, '\r', '\n', 0x7f, 0x85, 0x200b, 0x200d, 0x202e, 0x2066, 0xfeff, 0x2028, 0x2029} {
		if err := checkText("a"+string(r)+"b", maxTextBytes); err == nil {
			t.Errorf("U+%04X accepted", r)
		}
	}
	for _, text := range []string{"Erika Mustermann", "Jürgen Weiß-Öztürk", "1.2.276.0.76.4.49", "loa-substantial"} {
		if err := checkText(text, maxTextBytes); err != nil {
			t.Errorf("%q: %v", text, err)
		}
	}
}
