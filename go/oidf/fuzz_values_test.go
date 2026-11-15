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
	"encoding/json/jsontext"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"unicode"

	"github.com/gematik/zero-lab/go/openid"
)

// The fuzz targets of the values the relying party sends to an IDP or reads from one (servers.md rule 28). Each checks
// what it accepts against an oracle of its own, finds no control character in it, finds no input in an error, and,
// where a value would go out, counts the requests that leave: a refused value never reaches the network.

// hostileStrings are the seeds every string target starts from.
var hostileStrings = []string{
	"", "a", "a\r\nSet-Cookie: x=y", "a\x00b", "a\nb", "a\tb", "a\xffb", "a\xc0\xafb", "a\u202eb", "a\u200bb", "a\u2028b",
	"äöü", `a"b`, `a\b`, "javascript:alert(1)", "data:text/html,<script>x</script>", "file:///etc/passwd",
	"%2f", "%252f", "%5c", "%40", "%23", "..", "/../", strings.Repeat("a", 513), strings.Repeat("a", 2049),
}

// leaksInput reports whether an error quotes an input long enough to be told from the error's own words.
func leaksInput(err error, input string) bool {
	return err != nil && len(input) >= 16 && strings.Contains(err.Error(), input)
}

func hasControlOrFormat(value string) bool {
	return strings.ContainsFunc(value, func(r rune) bool { return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) })
}

var (
	base64URLValue = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
	verifierValue  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	nqcharToken    = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]{1,128}$`)
	nqscharText    = regexp.MustCompile(`^[\x20\x21\x23-\x5b\x5d-\x7e]*$`)
	vscharValue    = regexp.MustCompile(`^[\x20-\x7e]+$`)
)

// FuzzLoginValues sends a login of arbitrary state, nonce, verifier, scopes, acr values and claims. What reaches the
// PAR endpoint matches each value's grammar; a login refused sends nothing. openid.AuthorizationQuery checks scopes,
// acr values and claims generically, and checkLogin the federation's state, nonce and verifier, so the target lives
// here, where both run.
func FuzzLoginValues(f *testing.F) {
	f.Add("state_0-Z", "nonce_0-Z", testVerifier, "openid", LoAHigh, []byte(`{"id_token":{"acr":{"essential":true}}}`))
	for _, value := range hostileStrings {
		f.Add(value, value, value, value, value, []byte(value))
	}
	f.Add("s", "n", testVerifier, "openid openid", LoAHigh+" x", []byte(`{"id_token":{"a":1,"a":2}}`))
	f.Add("s", "n", testVerifier, "openid", "", []byte(strings.Repeat(`{"a":`, 8)+"1"+strings.Repeat("}", 8)))
	f.Add("s", "n", testVerifier, "openid", "", []byte(`{"id_token":{"a":{"essential":1e999}}}`))
	f.Add("s", "n", testVerifier, "openid", "", []byte(`{"id_token":{"a":NaN}}`))
	f.Add("s", "n", testVerifier, "openid", "", []byte("{\"id_token\":{\"\u202e\":null}}"))
	stub := newLoginStub(f)
	var sent atomic.Pointer[url.Values]
	counting := stub.answering(f, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			sent.Store(&r.PostForm)
		}
		answer(http.StatusCreated, "application/json", `{"request_uri":"urn:r","expires_in":60}`)(w, r)
	})
	f.Fuzz(func(t *testing.T, state, nonce, verifier, scope, acr string, claims []byte) {
		login := openid.Login{State: state, Nonce: nonce, Verifier: verifier, Claims: claims}
		if scope != "" {
			login.Scopes = strings.Split(scope, " ")
		}
		if acr != "" {
			login.ACRValues = strings.Split(acr, " ")
		}
		before := counting.requests.Load()
		_, err := stub.client.AuthenticationURL(t.Context(), login)
		if err != nil {
			if counting.requests.Load() != before && !errors.Is(err, ErrPARResponse) {
				t.Fatalf("a refused login reached the IDP: %v", err)
			}
			for _, input := range []string{state, nonce, verifier, scope, string(claims)} {
				if leaksInput(err, input) {
					t.Fatalf("the error quotes the input: %v", err)
				}
			}
			return
		}
		form := *sent.Load()
		if !base64URLValue.MatchString(form.Get("state")) || !base64URLValue.MatchString(form.Get("nonce")) {
			t.Fatalf("sent state %q, nonce %q", form.Get("state"), form.Get("nonce"))
		}
		if verifier != login.Verifier || !verifierValue.MatchString(verifier) {
			t.Fatalf("accepted verifier %q", verifier)
		}
		registered := strings.Fields(defaultMetadataScope)
		for token := range strings.SplitSeq(form.Get("scope"), " ") {
			if !nqcharToken.MatchString(token) || !slices.Contains(registered, token) {
				t.Fatalf("sent scope %q", form.Get("scope"))
			}
		}
		for value := range strings.SplitSeq(form.Get("acr_values"), " ") {
			if _, known := loaRank[value]; !known {
				t.Fatalf("sent acr_values %q", form.Get("acr_values"))
			}
		}
		if sentClaims := form.Get("claims"); sentClaims != string(claims) || len(claims) > 0 && !jsontext.Value(claims).IsValid() {
			t.Fatalf("sent claims %q for %q", sentClaims, claims)
		}
	})
}

// identifierOracle is the grammar of an entity identifier written apart from checkEntityIdentifier: labels of 1 to 63
// lowercase letters, digits and inner hyphens, a port without a leading zero, and non-empty segments of pchar
// without '%' and '@'. The port's upper bound and the dot segments are checked beside it.
var identifierOracle = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:([1-9][0-9]{0,4}))?((/[A-Za-z0-9._~!$&'()*+,;=:-]+)*)$`)

// FuzzEntityIdentifier feeds arbitrary issuers to checkEntityIdentifier. What it accepts matches identifierOracle,
// with a port up to 65535 and no dot segment; a refusal names no input.
func FuzzEntityIdentifier(f *testing.F) {
	for _, seed := range append([]string{
		"https://op.example", "https://op.example/tenant", "https://127.0.0.1:8443/op", "https://op.example/a/../b",
		"https://op.example/a%2fb", "https://op.example%40evil.example", "https://op.example\\@evil.example",
		"https://user@op.example", "https://op.example?x", "https://op.example#x", "HTTPS://OP.EXAMPLE", "http://op.example",
		"https://op.example/\u202e", "https://op.example\r\n", "https://op.example/" + strings.Repeat("a", 2048),
		"https://op.example/<script>", "https://op.example//x", "https://op.example:0", "https://op.example:99999",
		"https://op-.example", "https://op..example", "https://op.example.",
	}, hostileStrings...) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, iss string) {
		err := checkEntityIdentifier(iss)
		if err != nil {
			if !errors.Is(err, ErrEntityIdentifier) || leaksInput(err, iss) {
				t.Fatalf("refused as %v", err)
			}
			return
		}
		match := identifierOracle.FindStringSubmatch(iss)
		if len(iss) > maxEntityIdentifierBytes || match == nil {
			t.Fatalf("accepted %q", iss)
		}
		if port, err := strconv.Atoi(match[5]); match[5] != "" && (err != nil || port > 65535) {
			t.Fatalf("accepted the port of %q", iss)
		}
		for segment := range strings.SplitSeq(match[6], "/") {
			if segment == "." || segment == ".." {
				t.Fatalf("accepted a dot segment: %q", iss)
			}
		}
	})
}

// FuzzRedirectURI sends logins with arbitrary redirect URIs against a registered set. Only a URI byte for byte in the
// set is accepted, and a refused one sends neither a PAR nor a token request.
func FuzzRedirectURI(f *testing.F) {
	registered := []string{"https://rp.example/cb", "https://product.example/cb"}
	for _, seed := range append([]string{
		"https://rp.example/cb", "https://rp.example/cb/", "https://RP.example/cb", "https://rp.example/c",
		"https://rp.example/cb?x", "https://rp.example/cb#x", "https://rp.example/%63b", "https://rp.example:443/cb",
		"https://rp.example/x/../cb", "https://rp.example@evil.example/cb", "https://product.example/cb\x00",
	}, hostileStrings...) {
		f.Add(seed)
	}
	stub := newLoginStubWith(f, func(cfg *RelyingPartyConfig) { cfg.RelyingParty.RedirectURIs = registered })
	counting := stub.answering(f, answer(http.StatusCreated, "application/json", `{"request_uri":"urn:r","expires_in":60}`))
	f.Fuzz(func(t *testing.T, uri string) {
		login := validLogin()
		login.RedirectURI = uri
		// No redirect URI is the client's configured one.
		effective := login.RedirectFor(stub.client.redirectURI)
		known := false
		for _, candidate := range registered {
			known = known || candidate == effective
		}
		before := counting.requests.Load()
		_, err := stub.client.AuthenticationURL(t.Context(), login)
		if known != (err == nil) {
			t.Fatalf("%q: %v", uri, err)
		}
		if err != nil && (counting.requests.Load() != before || leaksInput(err, uri)) {
			t.Fatalf("%q: refused as %v after %d requests", uri, err, counting.requests.Load()-before)
		}
		if !known {
			if _, _, err := stub.client.ExchangeIdentity(t.Context(), login, "code"); !errors.Is(err, ErrRedirectURINotRegistered) || counting.requests.Load() != before {
				t.Fatalf("%q: the token request: %v", uri, err)
			}
		}
	})
}

// FuzzAuthorizationCode redeems arbitrary codes. A code reaches the token endpoint only if it is VSCHAR within bounds.
func FuzzAuthorizationCode(f *testing.F) {
	for _, seed := range append([]string{"SplxlOBeZQQYbYS6WxSbIA", "a b~", strings.Repeat("c", 2048)}, hostileStrings...) {
		f.Add(seed)
	}
	stub := newLoginStub(f)
	var sent atomic.Pointer[string]
	counting := stub.answering(f, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			code := r.PostForm.Get("code")
			sent.Store(&code)
		}
		answer(http.StatusBadRequest, "application/json", `{"error":"invalid_grant"}`)(w, r)
	})
	f.Fuzz(func(t *testing.T, code string) {
		before := counting.requests.Load()
		_, _, err := stub.client.ExchangeIdentity(t.Context(), nLogin(), code)
		if errors.Is(err, openid.ErrAuthorizationCode) {
			if counting.requests.Load() != before || leaksInput(err, code) {
				t.Fatalf("refused as %v after %d requests", err, counting.requests.Load()-before)
			}
			if vscharValue.MatchString(code) && len(code) <= 2048 {
				t.Fatalf("refused a VSCHAR code %q", code)
			}
			return
		}
		if !vscharValue.MatchString(code) || len(code) > 2048 || *sent.Load() != code {
			t.Fatalf("sent %q", code)
		}
	})
}

// FuzzPARResponse reads arbitrary PAR responses. What it accepts carries a request_uri of printable ASCII within
// bounds that starts with urn: or https://, and an expires_in of 1 to 600.
func FuzzPARResponse(f *testing.F) {
	for _, seed := range []string{
		`{"request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":60}`, `{"request_uri":"https://op.example/r","expires_in":600}`,
		`{"request_uri":"javascript:alert(1)","expires_in":60}`, `{"request_uri":"data:text/html,x","expires_in":60}`,
		`{"request_uri":"urn:r\r\nX: y","expires_in":60}`, `{"request_uri":"urn:r","request_uri":"urn:s","expires_in":60}`,
		`{"request_uri":"urn:r","expires_in":1e400}`, `{"request_uri":"urn:r","expires_in":NaN}`, `{"request_uri":"urn:r","expires_in":6e1}`,
		`{"request_uri":"urn:r","expires_in":-0}`, `{"REQUEST_URI":"urn:r","expires_in":60}`, "{\"request_uri\":\"urn:\xc0\xaf\",\"expires_in\":60}",
		`{"request_uri":"urn:r","expires_in":60,"x":` + strings.Repeat("[", 64) + strings.Repeat("]", 64) + `}`,
	} {
		f.Add([]byte(seed))
	}
	requestURI := regexp.MustCompile(`^(urn:|https://)[!-~]+$`)
	f.Fuzz(func(t *testing.T, body []byte) {
		pushed, err := parsePARResponse(body)
		if err != nil {
			if !errors.Is(err, ErrPARResponse) || leaksInput(err, string(body)) {
				t.Fatalf("refused as %v", err)
			}
			return
		}
		if len(pushed.RequestURI) > maxRequestURIBytes || !requestURI.MatchString(pushed.RequestURI) || pushed.ExpiresIn < 1 || pushed.ExpiresIn > maxPARLifetime {
			t.Fatalf("accepted %+v", pushed)
		}
	})
}

// FuzzErrorResponse reads arbitrary error responses. What it keeps is NQSCHAR within the bounds, so the error text
// holds no control character, and a refused response is not quoted.
func FuzzErrorResponse(f *testing.F) {
	for _, seed := range []string{
		`{"error":"invalid_request","error_description":"bad","gematik_code":"2004","gematik_uuid":"u","gematik_timestamp":1,"operation":"AUTHORIZE"}`,
		`{"error":"invalid_request","errorDescription":"camel"}`, `{"error":"a\r\nb"}`, `{"error":"a","error":"b"}`,
		`{"error":"x","error_description":"a\u202eb","error_uri":"javascript:alert(1)"}`, `{"error":"x","gematik_timestamp":1e999}`,
		`{"error":"x","error_description":"` + strings.Repeat("d", 300) + `"}`, "{\"error\":\"\xff\"}", `<html>no</html>`,
	} {
		f.Add([]byte(seed), "application/json")
	}
	f.Add([]byte(`{"error":"x"}`), "text/html")
	f.Fuzz(func(t *testing.T, body []byte, contentType string) {
		err := parseErrorResponse(&openid.Response{Status: http.StatusBadRequest, ContentType: contentType, Body: body})
		if leaksInput(err, string(body)) || hasControlOrFormat(err.Error()) {
			t.Fatalf("the error %q", err)
		}
		var oidcErr *Error
		if !errors.As(err, &oidcErr) {
			if !errors.Is(err, openid.ErrErrorResponse) {
				t.Fatalf("refused as %v", err)
			}
			return
		}
		if oidcErr.ErrorCode == "" || len(oidcErr.ErrorCode) > 64 || len(oidcErr.Description) > openid.MaxErrorDescriptionBytes {
			t.Fatalf("kept %+v", oidcErr)
		}
		for _, text := range []string{oidcErr.ErrorCode, oidcErr.Description, oidcErr.Operation, oidcErr.GematikCode, oidcErr.GematikUUID} {
			if !nqscharText.MatchString(text) || len(text) > openid.MaxErrorDescriptionBytes {
				t.Fatalf("kept %q", text)
			}
		}
	})
}
