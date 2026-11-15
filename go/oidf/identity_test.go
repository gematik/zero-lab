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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

// OIDC Core 2: auth_time is a NumericDate; it is required here and may not lie ahead of the clock.
func TestOIDCCore_2_AnAuthTimeThatIsMissingOrAheadIsRefused(t *testing.T) {
	for name, authTime := range map[string]any{
		"missing":          nil,
		"a string":         "1700000000",
		"ahead":            time.Now().Add(2 * time.Minute).Unix(),
		"past year 9999":   1e15,
		"negative":         -1,
		"null":             json.RawMessage("null"),
		"an object":        map[string]any{},
		"huge exponent":    json.RawMessage("1e999"),
		"a fraction ahead": float64(time.Now().Add(90*time.Second).UnixMilli()) / 1000,
	} {
		stub := newLoginStub(t)
		claims := validIDTokenClaims()
		if authTime == nil {
			delete(claims, "auth_time")
		} else {
			claims["auth_time"] = authTime
		}
		stub.idToken = stub.nestedToken(t, claims)
		if _, _, err := stub.client.ExchangeIdentity(t.Context(), nLogin(), "code"); err == nil {
			t.Errorf("%s: accepted", name)
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
		Issuer: "https://op.example", Subject: "subject", ID: "X123456789", DisplayName: "Erika Mustermann",
		GivenName: "Erika", FamilyName: "Mustermann", Profession: "1.2.276.0.76.4.49", Organization: "109500969",
		Birthdate: "1964-08-12", ACR: LoASubstantial, IDTokenVersion: "1.0.0",
	}
	got := *identity
	if got.AuthTime.Unix() != claims["auth_time"] || len(got.AMR) != 2 || got.AMR[1] != "urn:telematik:auth:mEW" || strings.Join(got.Scopes, " ") != strings.Join(defaultOPScopes, " ") {
		t.Errorf("auth_time %v, amr %v, scopes %v", got.AuthTime, got.AMR, got.Scopes)
	}
	got.AuthTime, got.AMR, got.Scopes = time.Time{}, nil, nil
	if fmt.Sprintf("%#v", []any{got.Subject, got.ID, got.DisplayName, got.GivenName, got.FamilyName, got.Profession, got.Organization, got.Birthdate, got.ACR, got.IDTokenVersion, got.Issuer}) !=
		fmt.Sprintf("%#v", []any{want.Subject, want.ID, want.DisplayName, want.GivenName, want.FamilyName, want.Profession, want.Organization, want.Birthdate, want.ACR, want.IDTokenVersion, want.Issuer}) {
		t.Errorf("identity = %+v", identity)
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
		if _, _, err := stub.client.ExchangeIdentity(t.Context(), nLogin(), "code"); !errors.Is(err, ErrIdentityClaim) {
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

// Servers rule 14: the personal claims of an identity never reach a log or an error by formatting, while what tells
// how and where the person logged in does.
func TestServerRule14_AnIdentityDoesNotLogItsPersonalClaims(t *testing.T) {
	identity := &Identity{
		Issuer: "https://idp.example", Subject: "subject-7f3a", ID: "X110411675", DisplayName: "Erika Mustermann-Display",
		GivenName: "ErikaGiven", FamilyName: "MustermannFamily", Birthdate: "1964-08-12",
		Profession: "1.2.276.0.76.4.49", Organization: "109500969", ACR: LoAHigh, AMR: []string{"urn:telematik:auth:eGK"},
		AuthTime: time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC), IDTokenVersion: "2.0.0", Scopes: []string{"openid", "urn:telematik:versicherter"},
	}
	personal := []string{identity.Subject, identity.ID, identity.DisplayName, identity.GivenName, identity.FamilyName, identity.Birthdate}
	shown := []string{identity.Issuer, identity.Profession, identity.Organization, identity.ACR, identity.AMR[0], "2026-11-15T08:00:00Z", identity.IDTokenVersion, "urn:telematik:versicherter"}

	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		outputs = append(outputs, fmt.Sprintf(verb, identity), fmt.Sprintf(verb, *identity))
	}
	outputs = append(outputs, identity.String(), fmt.Errorf("login: %v", identity).Error(), fmt.Errorf("login: %v", *identity).Error())
	var text, structured bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("login", "identity", identity)
	slog.New(slog.NewJSONHandler(&structured, nil)).Info("login", "identity", *identity)
	outputs = append(outputs, text.String(), structured.String())

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
	for _, output := range []string{identity.String(), text.String(), structured.String()} {
		for _, value := range shown {
			if !strings.Contains(output, value) {
				t.Errorf("%q lacks %q", output, value)
			}
		}
	}
	// The fields stay data a host can keep.
	stored, err := json.Marshal(identity)
	if err != nil || !bytes.Contains(stored, []byte(identity.ID)) {
		t.Errorf("JSON %s, %v", stored, err)
	}
}

func FuzzIdentity(f *testing.F) {
	f.Add([]byte(`{"sub":"s","acr":"gematik-ehealth-loa-high","amr":["urn:telematik:auth:eGK"],"auth_time":1700000000,"urn:telematik:claims:id":"X1","birthdate":"1964-08-12"}`))
	f.Add([]byte(`{"sub":"s","SUB":"t","acr":"x","amr":[],"auth_time":1e999}`))
	f.Add([]byte(`{"sub":"s\r\nX: y","acr":"gematik-ehealth-loa-high","amr":["a"],"auth_time":1}`))
	f.Add([]byte("{\"sub\":\"\xff\",\"acr\":\"gematik-ehealth-loa-high\",\"amr\":[\"a\"],\"auth_time\":1}"))
	f.Add([]byte(`{"sub":"s","acr":"gematik-ehealth-loa-high","amr":["a",null,1],"auth_time":-1,"urn:telematik:claims:display_name":{"x":1}}`))
	f.Add([]byte(`{"sub":"s","sub":"t","acr":"gematik-ehealth-loa-high","amr":["\u202e"],"auth_time":253402300799.9}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		identity, err := parseIdentity(payload, "https://op.example", "1.0.0")
		if err != nil {
			return
		}
		texts := []string{
			identity.Subject, identity.ID, identity.DisplayName, identity.GivenName, identity.FamilyName,
			identity.Profession, identity.Organization, identity.Birthdate, identity.ACR,
		}
		texts = append(texts, identity.AMR...)
		for _, text := range texts {
			if checkText(text, maxTextBytes) != nil {
				t.Fatalf("accepted %q", text)
			}
		}
		if identity.Subject == "" || len(identity.AMR) == 0 || len(identity.AMR) > maxAMREntries {
			t.Fatalf("accepted sub %q, amr %v", identity.Subject, identity.AMR)
		}
		if identity.AuthTime.Unix() < 0 || identity.AuthTime.Unix() > maxNumericDate {
			t.Fatalf("accepted auth_time %v", identity.AuthTime)
		}
	})
}
