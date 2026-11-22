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

package pep

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
)

// The JSON texts every reader of this package is held to: a member named twice, a name in another case and a string
// that is not UTF-8 (server rule 28).
var (
	memberTwice   = []byte(`{"sid":"s1","sid":"s2","id":{"sub":"u"},"iat":0,"exp":9999999999}`)
	nameOtherCase = []byte(`{"SID":"s1","id":{"sub":"u"},"iat":0,"exp":9999999999}`)
	notUTF8       = []byte("{\"sid\":\"s1\",\"id\":{\"sub\":\"\xff\"},\"iat\":0,\"exp\":9999999999}")
)

func TestServerRule28_TokenClaimNamedTwiceIsRefused(t *testing.T) {
	err := validateClaims([]byte(`{"exp":1,"exp":9999999999}`), time.Unix(100, 0), 0, "")
	if !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Fatalf("err = %v, want a member named twice", err)
	}
}

func TestServerRule28_TokenClaimNameInAnotherCaseIsNotTheClaim(t *testing.T) {
	if err := validateClaims([]byte(`{"EXP":1}`), time.Unix(100, 0), 0, ""); err != nil {
		t.Fatalf("EXP was read as exp: %v", err)
	}
	err := validateClaims([]byte(`{"AUD":"r"}`), time.Unix(100, 0), 0, "r")
	if err == nil || !strings.Contains(err.Error(), "audience does not name the resource") {
		t.Fatalf("err = %v, want AUD not taken for aud", err)
	}
	if got := (&AccessToken{Payload: []byte(`{"cnf":{"JKT":"abc"}}`)}).Thumbprint(); got != "" {
		t.Fatalf("JKT was read as jkt: %q", got)
	}
}

func TestServerRule28_TokenClaimNotUTF8IsRefused(t *testing.T) {
	err := validateClaims([]byte("{\"sub\":\"\xff\"}"), time.Unix(100, 0), 0, "")
	var syntactic *jsontext.SyntacticError
	if !errors.As(err, &syntactic) || !strings.Contains(syntactic.Error(), "invalid UTF-8") {
		t.Fatalf("err = %v, want invalid UTF-8", err)
	}
}

func TestServerRule28_KeySetMemberTwiceOrNotUTF8IsRefused(t *testing.T) {
	_, err := ParseJWKSet([]byte(`{"keys":[],"keys":[]}`))
	if !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Fatalf("keys twice: err = %v", err)
	}
	_, err = ParseJWKSet([]byte(`{"keys":[{"kty":"EC","kty":"RSA"}]}`))
	if !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Fatalf("kty twice: err = %v", err)
	}
	_, err = ParseJWKSet([]byte("{\"keys\":[],\"x\":\"\xff\"}"))
	if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("not UTF-8: err = %v", err)
	}
}

// "KEYS" is no set: the text is read as a single JWK, which has no kty.
func TestServerRule28_KeySetNameInAnotherCaseIsNotKeys(t *testing.T) {
	set, err := ParseJWKSet([]byte(`{"KEYS":[]}`))
	if err == nil {
		t.Fatalf("KEYS was read as keys: %+v", set)
	}
}

func TestServerRule28_SessionCookieClaimsAreReadExactly(t *testing.T) {
	if _, err := decodeSessionCookieClaims(memberTwice); !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Errorf("member twice: err = %v", err)
	}
	if _, err := decodeSessionCookieClaims(nameOtherCase); !errors.Is(err, json.ErrUnknownName) {
		t.Errorf("name in another case: err = %v", err)
	}
	if _, err := decodeSessionCookieClaims(notUTF8); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Errorf("not UTF-8: err = %v", err)
	}
	unknown := []byte(`{"sid":"s1","id":{"sub":"u"},"iat":0,"exp":9999999999,"admin":true}`)
	if _, err := decodeSessionCookieClaims(unknown); !errors.Is(err, json.ErrUnknownName) {
		t.Errorf("unknown member: err = %v", err)
	}
}

// Sealed with the right key, a snapshot the reader refuses opens no session.
func TestServerRule28_SessionCookieRefusedClaimsOpenNoSession(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	if _, _, ok := OpenSessionCookie(sealTestPayload(t, key, []byte(`{"sid":"s1","id":{"sub":"u"},"iat":0,"exp":9999999999}`)), [][]byte{key}, time.Unix(100, 0)); !ok {
		t.Fatal("the well-formed payload does not open")
	}
	for name, payload := range map[string][]byte{"member twice": memberTwice, "name in another case": nameOtherCase, "not UTF-8": notUTF8} {
		if _, _, ok := OpenSessionCookie(sealTestPayload(t, key, payload), [][]byte{key}, time.Unix(100, 0)); ok {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestServerRule28_EnforcerPolicyIsReadExactly(t *testing.T) {
	for name, c := range map[string]struct {
		policy string
		want   error
	}{
		"member twice":         {`{"type":"Scope","scope":"read","scope":"write"}`, jsontext.ErrDuplicateName},
		"name in another case": {`{"type":"AuthorizationDPoP","Nonce_Required":true}`, json.ErrUnknownName},
		"misspelled member":    {`{"type":"AuthorizationDPoP","nonce_require":true}`, json.ErrUnknownName},
	} {
		var h EnforcerHolder
		if err := json.Unmarshal([]byte(c.policy), &h); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	var h EnforcerHolder
	if err := json.Unmarshal([]byte("{\"type\":\"Scope\",\"scope\":\"\xff\"}"), &h); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Errorf("not UTF-8: err = %v", err)
	}
}

func FuzzDecodeSessionCookieClaims(f *testing.F) {
	f.Add([]byte(`{"sid":"s1","id":{"sub":"u"},"iat":0,"exp":9999999999}`))
	f.Add(memberTwice)
	f.Add(nameOtherCase)
	f.Add(notUTF8)
	f.Fuzz(func(t *testing.T, payload []byte) {
		c, err := decodeSessionCookieClaims(payload)
		if err != nil {
			return
		}
		again, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeSessionCookieClaims(again); err != nil {
			t.Fatalf("accepted claims do not read back: %v", err)
		}
	})
}

func FuzzEnforcerHolder(f *testing.F) {
	f.Add([]byte(`{"type":"AllOf","enforcers":[{"type":"AuthorizationBearer"},{"type":"Scope","scope":"read"}]}`))
	f.Add([]byte(`{"type":"Scope","scope":"read","scope":"write"}`))
	f.Add([]byte(`{"TYPE":"Deny"}`))
	f.Add([]byte(`{"type":"AuthorizationDPoP","Nonce_Required":true}`))
	f.Add([]byte("{\"type\":\"Scope\",\"scope\":\"\xff\"}"))
	f.Fuzz(func(_ *testing.T, policy []byte) {
		var h EnforcerHolder
		_ = json.Unmarshal(policy, &h)
	})
}

func rule28PEP(tb testing.TB) *PEP {
	tb.Helper()
	set, err := ParseJWKSet([]byte(testKeySet))
	if err != nil {
		tb.Fatal(err)
	}
	return rule28PEPWith(tb, set)
}

func rule28PEPWith(tb testing.TB, set *jose.JSONWebKeySet) *PEP {
	tb.Helper()
	p, err := NewBuilder().Resource("https://example.com").WithJWKSet(set).WithDPoPReplays(dpop.NewMemoryReplays(16, nil)).Build()
	if err != nil {
		tb.Fatal(err)
	}
	return p
}

// applyBearer runs the Bearer enforcer on a request with the Authorization headers given and reports the status
// of the answer and whether the guarded handler ran.
func applyBearer(p *PEP, authorization ...string) (status int, reached bool) {
	r := httptest.NewRequest(http.MethodGet, "https://example.com/guarded", nil)
	for _, value := range authorization {
		r.Header.Add("Authorization", value)
	}
	w := httptest.NewRecorder()
	(&EnforcerAuthorizationBearer{}).Apply(p.NewContext(w, r), func(Context) { reached = true })
	return w.Code, reached
}

// Server rule 28, headers: a request with more than one Authorization header, another scheme, credentials that
// are not token68 or credentials longer than an access token may be is malformed. It is answered 400 before a
// token is parsed; 401 is the answer to a token that was read and refused.
func TestServerRule28_BearerCredentialsAreCheckedBeforeATokenIsParsed(t *testing.T) {
	p := rule28PEP(t)
	wellFormed := "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
	for name, authorization := range map[string][]string{
		"two headers":           {"Bearer " + wellFormed, "Bearer " + wellFormed},
		"a second scheme":       {"Bearer " + wellFormed, "Basic dXNlcjpwYXNz"},
		"another scheme":        {"Basic dXNlcjpwYXNz"},
		"no credentials":        {"Bearer"},
		"empty credentials":     {"Bearer "},
		"two credentials":       {"Bearer " + wellFormed + " " + wellFormed},
		"a comma":               {"Bearer " + wellFormed + "," + wellFormed},
		"a control character":   {"Bearer " + wellFormed + "\x00"},
		"not ASCII":             {"Bearer " + wellFormed + "é"},
		"padding in the middle": {"Bearer eyJ=.e30.c2ln"},
		"longer than a token":   {"Bearer " + strings.Repeat("a", maxAccessTokenBytes+1)},
	} {
		if status, reached := applyBearer(p, authorization...); status != http.StatusBadRequest || reached {
			t.Errorf("%s: status %d, handler reached %v", name, status, reached)
		}
	}
	for name, authorization := range map[string]string{
		"a token68 value that is no JWS": "Bearer " + wellFormed,
		"the scheme in another case":     "bEARER " + wellFormed,
		"several spaces":                 "Bearer    " + wellFormed,
		"as long as a token may be":      "Bearer " + strings.Repeat("a", maxAccessTokenBytes),
	} {
		if status, reached := applyBearer(p, authorization); status != http.StatusUnauthorized || reached {
			t.Errorf("%s: status %d, handler reached %v", name, status, reached)
		}
	}
	if status, reached := applyBearer(p); status != http.StatusUnauthorized || reached {
		t.Errorf("no header: status %d, handler reached %v", status, reached)
	}
}

// Server rule 28, bodies: a JWS or JWE is checked against its compact form and size before it is decoded.
func TestServerRule28_ATokenIsCheckedAgainstCompactFormAndSizeBeforeItIsDecoded(t *testing.T) {
	const jws, jwe, none = 3, 5, -1
	for name, c := range map[string]struct {
		raw          string
		parts, empty int
		ok           bool
	}{
		"a JWS":                       {"aA0-_.b.c", jws, none, true},
		"a JWE of direct encryption":  {"a..b.c.d", jwe, 1, true},
		"two segments":                {"a.b", jws, none, false},
		"four segments":               {"a.b.c.d", jws, none, false},
		"no signature":                {"a.b.", jws, none, false},
		"no header":                   {".b.c", jws, none, false},
		"empty":                       {"", jws, none, false},
		"padding":                     {"a=.b.c", jws, none, false},
		"standard base64":             {"a+/.b.c", jws, none, false},
		"a space":                     {"a .b.c", jws, none, false},
		"a line break":                {"a.b.c\n", jws, none, false},
		"a JWE with an encrypted key": {"a.k.b.c.d", jwe, 1, false},
		"a JWE without ciphertext":    {"a..b..d", jwe, 1, false},
		"a JWS where a JWE is read":   {"a.b.c", jwe, 1, false},
		"at the limit":                {strings.Repeat("a", 60) + ".b.c", jws, none, true},
		"over the limit":              {strings.Repeat("a", 61) + ".b.c", jws, none, false},
	} {
		if err := checkCompact(c.raw, 64, c.parts, c.empty); (err == nil) != c.ok {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	set, err := ParseJWKSet([]byte(testKeySet))
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", maxAccessTokenBytes) + ".b.c"
	_, _, err = verifyJWS(long, set)
	if err == nil {
		t.Fatal("an access token over the limit was read")
	}
	if !strings.Contains(err.Error(), "longer") || strings.Contains(err.Error(), "aaaa") {
		t.Errorf("the refusal does not name the limit, or quotes the token: %v", err)
	}
}

// Server rule 28, cookies: a cookie's value is bounded and parsed before use. A snapshot longer than a browser
// keeps, or outside the compact form of direct encryption, is refused before it is decrypted.
func TestServerRule28_ASessionCookieIsBoundedAndCheckedBeforeItIsOpened(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	now := time.Unix(1_700_000_000, 0)
	sealed := sealSessionCookieForTest(t, key, sessionCookieClaims{SID: "s1", Identity: map[string]any{"sub": "u"}, IssuedAt: now.Unix(), Expiry: now.Unix() + 60})
	if _, sid, ok := OpenSessionCookie(sealed, [][]byte{key}, now); !ok || sid != "s1" {
		t.Fatalf("a snapshot of this package was refused: ok=%v sid=%q", ok, sid)
	}
	header, rest, _ := strings.Cut(sealed, ".")
	for name, value := range map[string]string{
		"an encrypted key":     header + ".a" + rest,
		"a sixth segment":      sealed + ".a",
		"padding":              sealed + "=",
		"a space":              sealed + " ",
		"longer than a cookie": header + "." + rest + strings.Repeat("a", maxSessionCookieBytes),
		"a JWS":                "a.b.c",
		"empty":                "",
	} {
		if _, _, ok := OpenSessionCookie(value, [][]byte{key}, now); ok {
			t.Errorf("%s: opened", name)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "https://example.com/guarded", nil)
	r.Header.Set("Cookie", "sid="+sealed+".a")
	w := httptest.NewRecorder()
	reached := false
	NewEnforcerSessionCookie("sid", [][]byte{key}).Apply(rule28PEP(t).NewContext(w, r), func(Context) { reached = true })
	if reached || w.Code != ErrSessionRequired.HTTPStatus {
		t.Errorf("the enforcer: status %d, handler reached %v", w.Code, reached)
	}
}

func sealSessionCookieForTest(t *testing.T, key []byte, claims sessionCookieClaims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object, err := encrypter.Encrypt(payload)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// FuzzBearerCredentials asserts what accepted Bearer credentials are: the request had one Authorization header
// of the Bearer scheme, and the credentials are a token68 value within the size of an access token.
func FuzzBearerCredentials(f *testing.F) {
	f.Add("Bearer eyJhbGciOiJFUzI1NiJ9.e30.c2ln", "")
	f.Add("Bearer a", "Bearer b")
	f.Add("bearer  a==", "")
	f.Add("Bearer a b", "")
	f.Add("Bearer a\r\nX-Injected: 1", "")
	f.Add("Bearer a\x00", "")
	f.Add("Bearer \xff\xfe", "")
	f.Add("Bearer \u202ea", "")
	f.Add("Bearer%20a", "")
	f.Add("DPoP a", "Bearer a")
	f.Add("Bearer "+strings.Repeat("a", maxAccessTokenBytes+1), "")
	f.Fuzz(func(t *testing.T, first, second string) {
		r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		r.Header.Add("Authorization", first)
		if second != "" {
			r.Header.Add("Authorization", second)
		}
		token, err := (&pepContext{request: r}).bearerCredentials()
		if err != nil {
			if token != "" {
				t.Fatalf("a refusal returned credentials")
			}
			if !errors.Is(err, ErrNoAuthorizationHeader) && !errors.Is(err, ErrInvalidAuthorizationHeader) {
				t.Fatalf("the refusal is none of the two fixed denials: %v", err)
			}
			return
		}
		if second != "" {
			t.Fatalf("credentials taken from one of two headers")
		}
		if !dpop.IsToken68(token) || len(token) > maxAccessTokenBytes {
			t.Fatalf("accepted credentials are no token68 value within the limit")
		}
		scheme, rest, _ := strings.Cut(first, " ")
		if !strings.EqualFold(scheme, "Bearer") || strings.TrimLeft(rest, " ") != token {
			t.Fatalf("accepted credentials are not those of a Bearer header")
		}
	})
}

// FuzzBearerEnforcer sends arbitrary Authorization headers through the enforcer. Its key is made here and signs
// nothing, so no input holds a token it verifies: the guarded handler must never run, and every refusal is a
// 400 or a 401.
func FuzzBearerEnforcer(f *testing.F) {
	var fixture legacyVerdicts
	raw, err := os.ReadFile("testdata/legacy_verdicts.json")
	if err != nil {
		f.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		f.Fatal(err)
	}
	for _, c := range fixture.Tokens {
		f.Add("Bearer "+c.Token, "")
	}
	f.Add("Bearer a.b.c", "Bearer a.b.c")
	f.Add("Bearer "+strings.Repeat("a", maxAccessTokenBytes+1), "")
	f.Add("Bearer a.b.c\r\n", "")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	p := rule28PEPWith(f, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "unused", Algorithm: "ES256"}}})
	f.Fuzz(func(t *testing.T, first, second string) {
		authorization := []string{first}
		if second != "" {
			authorization = append(authorization, second)
		}
		status, reached := applyBearer(p, authorization...)
		if reached {
			t.Fatalf("the handler ran")
		}
		if status != http.StatusBadRequest && status != http.StatusUnauthorized {
			t.Fatalf("status %d", status)
		}
	})
}
