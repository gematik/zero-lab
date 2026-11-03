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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The testdata/legacy_*.json fixtures were made by the code of commit a11372a, the last one built on the previous
// JOSE library: tokens and cookies from its issuing paths, and for hostile inputs the verdict it reached.

type legacyTokenCase struct {
	Name        string `json:"name"`
	JWKS        string `json:"jwks"`
	Resource    string `json:"resource"`
	Token       string `json:"token"`
	OldAccepted bool   `json:"old_accepted"`
}

type legacyVerdicts struct {
	Tokens []legacyTokenCase `json:"tokens"`
	Sets   []struct {
		Name        string `json:"name"`
		JWKS        string `json:"jwks"`
		OldAccepted bool   `json:"old_accepted"`
	} `json:"sets"`
	Cookies []struct {
		Name        string `json:"name"`
		Token       string `json:"token"`
		OldAccepted bool   `json:"old_accepted"`
	} `json:"cookies"`
	CookieKey string `json:"cookie_key_b64"`
}

func readFixture(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

const testKeySet = `{"keys":[{"crv":"P-256","kid":"NFXYr6yPkItn_euY_fvaiKetekY0fFcZIupXwGaesjo","kty":"EC","x":"CSe6WWOsFaUSjp437htjVBkDdF5LRj_ZvBfxQ4BecH4","y":"rhz8yAOajNwAH3DTujwepcsUQI-cBeSMGyCuByhbh-4"},{"crv":"P-256","kid":"QcNB-yJBGj1M0dzrWuT_Vi3_yWMWBXkznqSSY5KPcB8","kty":"EC","x":"tFrHA6uGuTvbX52h7uakJcGymGZiU5VA0gBhPEL4QoI","y":"gyo2PzEeyVTP7DdpQW3CT5T2ANLlt18tcH0H9TnfIt8"}]}`

// refusedSinceMigration lists what the old code accepted and this one refuses on purpose, each with its reason. A
// token not listed here keeps its old verdict: nothing refused before may pass now.
var refusedSinceMigration = map[string]string{
	"no_alg":               "RFC 7515 Section 4.1.1 makes alg mandatory; it was guessed from the key",
	"hs256_oct_key_in_set": "no HS* at all, a key set is public material",
	"crit_header":          "RFC 7515 Section 4.1.11: a crit extension that is not understood invalidates the JWS",
	"nested_jws_payload":   "a claims set is a JSON object, not another JWS",
	"exp_string":           "RFC 7519 Section 2: a NumericDate is a number",
	"iss_null":             "RFC 7519 Section 4.1.1: iss is a string",
	"private_key_in_set":   "a key set is public material; a private key there is a mistake to surface",
}

func TestLegacyVerdicts_NothingRefusedBeforeIsAcceptedNow(t *testing.T) {
	var fixture legacyVerdicts
	readFixture(t, "legacy_verdicts.json", &fixture)
	if len(fixture.Tokens) == 0 {
		t.Fatal("no cases in the fixture")
	}
	for _, c := range fixture.Tokens {
		t.Run(c.Name, func(t *testing.T) {
			jwks := c.JWKS
			if jwks == "" {
				jwks = testKeySet
			}
			set, err := ParseJWKSet([]byte(jwks))
			if err != nil {
				if c.OldAccepted {
					t.Fatalf("key set of an accepted case refused: %v", err)
				}
				return
			}
			p, err := NewBuilder().WithJWKSet(set).Resource(c.Resource).Build()
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.VerifyAccessToken(c.Token)
			want := c.OldAccepted
			if _, refused := refusedSinceMigration[c.Name]; refused {
				if !c.OldAccepted {
					t.Fatal("listed as newly refused, but the old code refused it too")
				}
				want = false
			}
			if accepted := err == nil; accepted != want {
				t.Fatalf("accepted = %v, want %v (old: %v): %v", accepted, want, c.OldAccepted, err)
			}
		})
	}
}

func TestLegacyVerdicts_KeySetsKeepTheirVerdict(t *testing.T) {
	var fixture legacyVerdicts
	readFixture(t, "legacy_verdicts.json", &fixture)
	for _, c := range fixture.Sets {
		t.Run(c.Name, func(t *testing.T) {
			if _, err := ParseJWKSet([]byte(c.JWKS)); (err == nil) != c.OldAccepted {
				t.Fatalf("accepted = %v, want %v: %v", err == nil, c.OldAccepted, err)
			}
		})
	}
}

// Only A256GCM in compact form was ever minted, so nothing sealed depends on the other forms the old code opened.
func TestLegacyVerdicts_SessionCookieOpensOnlyWhatWasEverMinted(t *testing.T) {
	var fixture legacyVerdicts
	readFixture(t, "legacy_verdicts.json", &fixture)
	key, err := base64.StdEncoding.DecodeString(fixture.CookieKey)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"a256gcm": true, "a256gcm_deflate": true, "a128cbc_hs256": false, "a256gcm_json": false}
	for _, c := range fixture.Cookies {
		t.Run(c.Name, func(t *testing.T) {
			if !c.OldAccepted {
				t.Fatal("the old code should have opened every case")
			}
			if _, _, ok := OpenSessionCookie(c.Token, [][]byte{key}); ok != want[c.Name] {
				t.Fatalf("opened = %v, want %v", ok, want[c.Name])
			}
		})
	}
}

type legacyIssued struct {
	JWKS        json.RawMessage `json:"jwks"`
	AccessToken string          `json:"access_token"`
	JKT         string          `json:"jkt"`
	SnapshotKey string          `json:"snapshot_key_b64"`
	Snapshot    string          `json:"snapshot"`
	SID         string          `json:"sid"`
	Identity    map[string]any  `json:"identity"`
}

func TestLegacySessionCookieFromOldMintStillOpens(t *testing.T) {
	var fixture legacyIssued
	readFixture(t, "legacy_issued.json", &fixture)
	key, err := base64.StdEncoding.DecodeString(fixture.SnapshotKey)
	if err != nil {
		t.Fatal(err)
	}
	identity, sid, ok := OpenSessionCookie(fixture.Snapshot, [][]byte{key})
	if !ok {
		t.Fatal("a snapshot sealed by the old code does not open")
	}
	if sid != fixture.SID {
		t.Fatalf("sid = %q", sid)
	}
	got, _ := json.Marshal(identity)
	want, _ := json.Marshal(fixture.Identity)
	if !bytes.Equal(got, want) {
		t.Fatalf("identity = %s, want %s", got, want)
	}
}

func TestLegacyAccessTokenFromOldPDPStillVerifiesAndKeepsItsBinding(t *testing.T) {
	var fixture legacyIssued
	readFixture(t, "legacy_issued.json", &fixture)
	set, err := ParseJWKSet(fixture.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewBuilder().WithJWKSet(set).Resource("https://rs.example").Build()
	if err != nil {
		t.Fatal(err)
	}
	token, err := p.VerifyAccessToken(fixture.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if got := token.Thumbprint(); got != fixture.JKT {
		t.Fatalf("cnf.jkt = %q, want %q", got, fixture.JKT)
	}
}

func TestSkewIsNegativeNeverAccepted(t *testing.T) {
	if err := validateClaims([]byte(`{}`), time.Now(), -time.Second, ""); err == nil {
		t.Fatal("a negative skew was accepted")
	}
}

// RFC 7519 Sections 4.1.4 and 4.1.5: the boundaries of exp, nbf and iat under the skew.
func TestRFC7519_TimeClaimsHoldAtTheirBoundaries(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	const skew = time.Minute
	claim := func(name string, at time.Time) string {
		return `{"` + name + `":` + strconv.FormatFloat(float64(at.UnixNano())/1e9, 'f', 3, 64) + `}`
	}
	for _, c := range []struct {
		name    string
		payload string
		now     time.Time
		wantErr bool
	}{
		{"exp just inside the skew", claim("exp", base), base.Add(skew - time.Millisecond), false},
		{"exp on the instant is refused", claim("exp", base), base.Add(skew), true},
		{"exp past the skew", claim("exp", base), base.Add(skew + time.Second), true},
		{"fractional exp counts from its whole second", `{"exp":1700000000.9}`, base.Add(skew + 500*time.Millisecond), true},
		{"nbf on the edge of the skew", claim("nbf", base), base.Add(-skew), false},
		{"nbf before the skew", claim("nbf", base), base.Add(-skew - time.Millisecond), true},
		{"iat on the edge of the skew", claim("iat", base), base.Add(-skew), false},
		{"iat before the skew", claim("iat", base), base.Add(-skew - time.Millisecond), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := validateClaims([]byte(c.payload), c.now, skew, ""); (err != nil) != c.wantErr {
				t.Fatalf("err = %v, want error %v", err, c.wantErr)
			}
		})
	}
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, payload string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The set holds one key, the case where a verifier is tempted to use it without being told to.
func TestTokenWithoutKidIsRefusedEvenWithOneKeyInTheSet(t *testing.T) {
	key := newTestKey(t)
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "only"}}}
	if _, err := verifyJWS(signES256(t, key, "only", `{}`), set); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, err := verifyJWS(signES256(t, key, "", `{}`), set); err == nil {
		t.Fatal("a token without a kid was accepted")
	}
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(`{"crv":"P-256","d":"wCAQdVx6LR3BRFACmporyQ2tMGu755WNJsfhu5sx3Qk","kty":"EC","x":"CSe6WWOsFaUSjp437htjVBkDdF5LRj_ZvBfxQ4BecH4","y":"rhz8yAOajNwAH3DTujwepcsUQI-cBeSMGyCuByhbh-4"}`), &jwk); err != nil {
		t.Fatal(err)
	}
	return jwk.Key.(*ecdsa.PrivateKey)
}

func TestRSAKeyBelow2048BitsCannotVerify(t *testing.T) {
	short, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // the point of the test: a key too short to rely on
	if err != nil {
		t.Fatal(err)
	}
	if publicKeyFits(&short.PublicKey, jose.RS256) {
		t.Fatal("a 1024-bit key fits RS256")
	}
}

func TestThumbprintReadsCnfJktOnly(t *testing.T) {
	for payload, want := range map[string]string{
		`{"cnf":{"jkt":"abc"}}`: "abc",
		`{"CNF":{"jkt":"abc"}}`: "",
		`{"cnf":{"JKT":"abc"}}`: "",
		`{"cnf":{"jkt":1}}`:     "",
		`{"cnf":"abc"}`:         "",
		`{}`:                    "",
	} {
		if got := (&AccessToken{Payload: []byte(payload)}).Thumbprint(); got != want {
			t.Errorf("%s: %q, want %q", payload, got, want)
		}
	}
}

// A hostile token must only ever be refused, never crash the guard; what is accepted has held every claim check.
func FuzzVerifyAccessToken(f *testing.F) {
	var fixture legacyVerdicts
	raw, err := os.ReadFile("testdata/legacy_verdicts.json")
	if err != nil {
		f.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		f.Fatal(err)
	}
	for _, c := range fixture.Tokens {
		f.Add(c.Token)
	}
	set, err := ParseJWKSet([]byte(testKeySet))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(_ *testing.T, token string) {
		payload, err := verifyJWS(token, set)
		if err != nil {
			return
		}
		_ = validateClaims(payload, time.Now(), time.Minute, "https://example.com")
		_ = (&AccessToken{Payload: payload}).Thumbprint()
	})
}

func FuzzValidateClaims(f *testing.F) {
	f.Add([]byte(`{"exp":1,"nbf":"x","aud":["a",null]}`))
	f.Add([]byte(`{"exp":1e400}`))
	f.Add([]byte(strconv.FormatFloat(math.MaxFloat64, 'g', -1, 64)))
	f.Fuzz(func(_ *testing.T, payload []byte) {
		_ = validateClaims(payload, time.Now(), time.Minute, "r")
	})
}

func FuzzParseJWKSet(f *testing.F) {
	f.Add([]byte(`{"keys":[{"kty":"EC"}]}`))
	f.Add([]byte(`{"kty":"oct","k":"AA"}`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseJWKSet(data)
	})
}

func FuzzOpenSessionCookie(f *testing.F) {
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..a.b.c")
	key := bytes.Repeat([]byte{7}, 32)
	f.Fuzz(func(_ *testing.T, token string) {
		_, _, _ = OpenSessionCookie(token, [][]byte{key})
	})
}

func TestWithJWKSetPathFailsTheBuildOnAnUnreadableOrInvalidFile(t *testing.T) {
	dir := t.TempDir()
	valid, invalid := dir+"/valid.json", dir+"/invalid.json"
	if err := os.WriteFile(valid, []byte(testKeySet), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalid, []byte(`{"keys":[{"kty":"nope"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBuilder().WithJWKSetPath(valid).Build(); err != nil {
		t.Fatalf("valid file: %v", err)
	}
	for _, path := range []string{invalid, dir + "/absent.json"} {
		if _, err := NewBuilder().WithJWKSetPath(path).Build(); err == nil {
			t.Fatalf("%s: a PEP was built without its keys", path)
		}
	}
}
