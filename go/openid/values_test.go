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
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// nastyStrings are hostile values every field is fed: injection of CR, LF and NUL, invalid and overlong UTF-8, bidi
// and zero-width characters, URIs of dangerous schemes and quotes that would end a JSON string.
var nastyStrings = map[string]string{
	"CRLF":            "a\r\nSet-Cookie: x=y",
	"NUL":             "a\x00b",
	"tab":             "a\tb",
	"invalid UTF-8":   "a\xffb",
	"overlong UTF-8":  "a\xc0\xafb",
	"bidi override":   "a\u202eb",
	"zero-width":      "a\u200bb",
	"line separator":  "a\u2028b",
	"non-ASCII":       "äöü",
	"quote":           `a"b`,
	"backslash":       `a\b`,
	"javascript: URI": "javascript:alert(1)\n",
}

func TestOWASP_InputValidation_AuthorizationCode(t *testing.T) {
	for name, code := range nastyStrings {
		if name == "quote" || name == "backslash" {
			continue
		}
		if err := CheckAuthorizationCode(code); !errors.Is(err, ErrAuthorizationCode) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, code := range map[string]string{"empty": "", "overlong": strings.Repeat("a", maxAuthorizationCodeBytes+1)} {
		if err := CheckAuthorizationCode(code); !errors.Is(err, ErrAuthorizationCode) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, code := range []string{"a", strings.Repeat("~", maxAuthorizationCodeBytes), `a b"c\d`, "SplxlOBeZQQYbYS6WxSbIA"} {
		if err := CheckAuthorizationCode(code); err != nil {
			t.Errorf("%q: %v", code, err)
		}
	}
}

func TestOWASP_InputValidation_JSONObject(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate key":            `{"a":1,"a":2}`,
		"duplicate key by escape":  `{"a":1,"a":2}`,
		"nested duplicate":         `{"a":{"b":1,"b":2}}`,
		"deeply nested":            strings.Repeat(`{"a":`, ResponseDepth+1) + "1" + strings.Repeat("}", ResponseDepth+1),
		"invalid UTF-8":            "{\"a\":\"\xff\"}",
		"overlong UTF-8":           "{\"a\":\"\xc0\xaf\"}",
		"no object":                `["a"]`,
		"null":                     `null`,
		"data after the object":    `{} {}`,
		"truncated":                `{"a":`,
		"NaN":                      `{"a":NaN}`,
		"too many members":         manyMembers(ResponseMembers + 1),
		"control character in key": "{\"a\x01\":1}",
	} {
		if err := CheckJSONObject([]byte(body), ResponseDepth, ResponseMembers); !errors.Is(err, ErrJSON) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := CheckJSONObject([]byte(` {"a":[{"b":1},{"b":1}],"c":"\u202e"} `), ResponseDepth, ResponseMembers); err != nil {
		t.Errorf("the same name in two objects, or an escaped format character, is no duplicate: %v", err)
	}
}

// manyMembers is an object of n members with distinct names.
func manyMembers(n int) string {
	members := make([]string, n)
	for i := range members {
		members[i] = fmt.Sprintf(`"m%d":0`, i)
	}
	return "{" + strings.Join(members, ",") + "}"
}

const testJWE = "eyJhbGciOiJFQ0RILUVTIn0..aXY.Y2lwaGVy.dGFn"

func TestOWASP_InputValidation_TokenResponse(t *testing.T) {
	for name, body := range map[string]string{ //nolint:gosec // G101: token responses made up to be refused, no credentials
		"no token_type":                `{"access_token":"a"}`,
		"token_type mac":               `{"token_type":"mac"}`,
		"token_type with CRLF":         `{"token_type":"Bearer\r\n"}`,
		"token_type a number":          `{"token_type":1}`,
		"access_token with CRLF":       `{"token_type":"Bearer","access_token":"a\r\nb"}`,
		"access_token with NUL":        `{"token_type":"Bearer","access_token":"a\u0000b"}`,
		"access_token not ASCII":       `{"token_type":"Bearer","access_token":"ä"}`,
		"access_token empty":           `{"token_type":"Bearer","access_token":""}`,
		"access_token overlong":        `{"token_type":"Bearer","access_token":"` + strings.Repeat("a", maxBearerBytes+1) + `"}`,
		"refresh_token with bidi":      `{"token_type":"Bearer","refresh_token":"a\u202eb"}`,
		"id_token of four parts":       `{"token_type":"Bearer","id_token":"a.b.c.d"}`,
		"id_token of six parts":        `{"token_type":"Bearer","id_token":"a.b.c.d.e.f"}`,
		"id_token without header":      `{"token_type":"Bearer","id_token":".b.c"}`,
		"id_token with padding":        `{"token_type":"Bearer","id_token":"YQ==.b.c"}`,
		"id_token with a space":        `{"token_type":"Bearer","id_token":"a .b.c"}`,
		"id_token overlong":            `{"token_type":"Bearer","id_token":"` + strings.Repeat("a", MaxIDTokenBytes) + `.b.c"}`,
		"scope with double space":      `{"token_type":"Bearer","scope":"openid  email"}`,
		"scope with quote":             `{"token_type":"Bearer","scope":"open\"id"}`,
		"expires_in negative":          `{"token_type":"Bearer","expires_in":-1}`,
		"expires_in exponent":          `{"token_type":"Bearer","expires_in":1e3}`,
		"expires_in fraction":          `{"token_type":"Bearer","expires_in":1.5}`,
		"expires_in huge":              `{"token_type":"Bearer","expires_in":99999999999999999999}`,
		"expires_in a word":            `{"token_type":"Bearer","expires_in":"soon"}`,
		"duplicate id_token":           `{"token_type":"Bearer","id_token":"a.b.c","id_token":"d.e.f"}`,
		"invalid UTF-8":                "{\"token_type\":\"Bearer\",\"x\":\"\xff\"}",
		"deeply nested unknown member": `{"token_type":"Bearer","x":` + strings.Repeat("[", ResponseDepth) + strings.Repeat("]", ResponseDepth) + `}`,
	} {
		if _, err := ParseTokenResponse([]byte(body)); !errors.Is(err, ErrTokenResponse) {
			t.Errorf("%s: %v", name, err)
		}
	}
	response, err := ParseTokenResponse([]byte(`{"token_type":"dpop","access_token":"a b~","id_token":"` + testJWE + `","ID_TOKEN":"x","scope":"openid email","expires_in":300,"unknown":{"x":[1]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if response.TokenType != "dpop" || response.IDTokenRaw != testJWE || response.ExpiresIn != 300 || response.Scope != "openid email" {
		t.Errorf("read %+v: members are read by their exact names, unknown ones ignored, nothing repaired", response)
	}
}

func TestOWASP_InputValidation_ErrorResponse(t *testing.T) {
	for name, body := range map[string]string{
		"no error":            `{"error_description":"x"}`,
		"empty error":         `{"error":""}`,
		"error with CRLF":     `{"error":"invalid_grant\r\nX: y"}`,
		"error with quote":    `{"error":"a\"b"}`,
		"error not ASCII":     `{"error":"ä"}`,
		"error overlong":      `{"error":"` + strings.Repeat("a", maxErrorCodeBytes+1) + `"}`,
		"error a number":      `{"error":1}`,
		"error named twice":   `{"error":"a","error":"b"}`,
		"error by other case": `{"ERROR":"invalid_grant"}`,
		"no object":           `"invalid_grant"`,
	} {
		if _, err := ParseErrorResponse([]byte(body)); !errors.Is(err, ErrErrorResponse) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, description := range map[string]string{
		"CRLF": `a\r\nb`, "NUL": `a\u0000b`, "bidi": `a\u202eb`, "not ASCII": "ä", "markup quote": `\"<b>`,
		"overlong": strings.Repeat("a", MaxErrorDescriptionBytes+1), "a number": "",
	} {
		body := `{"error":"invalid_grant","error_description":"` + description + `","error_uri":"javascript:alert(1)"}`
		if name == "a number" {
			body = `{"error":"invalid_grant","error_description":1}`
		}
		refusal, err := ParseErrorResponse([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if refusal.Code != "invalid_grant" || refusal.Description != "" {
			t.Errorf("%s: kept %+v, the description is dropped", name, refusal)
		}
	}
	refusal, err := ParseErrorResponse([]byte(`{"error":"invalid_grant","error_description":"code <expired>"}`))
	if err != nil || refusal.Error() != "invalid_grant: code <expired>" {
		t.Errorf("%v %v", refusal, err)
	}
}

func TestServerRule28_AResponseIsDeclaredAsJSON(t *testing.T) {
	for _, contentType := range []string{"application/json", "application/json; charset=utf-8", "Application/JSON;charset=UTF-8"} {
		if err := (&Response{ContentType: contentType}).CheckJSON(); err != nil {
			t.Errorf("%q: %v", contentType, err)
		}
	}
	for _, contentType := range []string{
		"", "text/html", "text/plain; charset=utf-8", "application/json; charset=iso-8859-1", "application/jsonx",
		"application/json; boundary=x", "application/json; charset=utf-8; charset=utf-8", "application/json\r\nX: y",
	} {
		if err := (&Response{ContentType: contentType}).CheckJSON(); !errors.Is(err, ErrResponseContentType) {
			t.Errorf("%q: %v", contentType, err)
		}
	}
}

// compactJOSE is an oracle of the compact form, written apart from isCompactJOSE.
var compactJOSE = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*){2}$|^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*){4}$`)

// FuzzTokenResponse feeds arbitrary bodies to ParseTokenResponse. Properties: what it accepts matches the grammar of
// each member, checked by oracles of the test's own, holds no control character, and a refusal never quotes the body.
func FuzzTokenResponse(f *testing.F) {
	for _, seed := range []string{
		`{"token_type":"Bearer","access_token":"a","id_token":"` + testJWE + `","scope":"openid","expires_in":300}`,
		`{"token_type":"DPoP","expires_in":"300"}`, `{"token_type":"Bearer","id_token":"a.b.c.d"}`,
		`{"token_type":"Bearer","id_token":"a.b.c.d.e.f"}`, `{"token_type":"Bearer","access_token":"a\r\nb"}`,
		`{"token_type":"Bearer","token_type":"DPoP"}`, `{"token_type":"Bearer","expires_in":1e309}`,
		`{"token_type":"Bearer","expires_in":NaN}`, `{"token_type":"Bearer","expires_in":-0}`,
		"{\"token_type\":\"Bearer\",\"scope\":\"\xc0\xaf\"}", `{"token_type":"Bearer","scope":"a\u200bb"}`,
		`{"token_type":"Bearer","id_token":"eyJhbGciOiJub25lIn0.e30."}`,
		`{"token_type":"Bearer","x":` + strings.Repeat("[", 64) + strings.Repeat("]", 64) + `}`,
		`{"token_type":"Bearer","id_token":"` + strings.Repeat("A", MaxIDTokenBytes) + `.b.c"}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		response, err := ParseTokenResponse(body)
		if err != nil {
			if len(body) >= 16 && strings.Contains(err.Error(), string(body)) {
				t.Fatalf("the error quotes the body: %v", err)
			}
			return
		}
		if !strings.EqualFold(response.TokenType, "bearer") && !strings.EqualFold(response.TokenType, "dpop") {
			t.Fatalf("token_type %q", response.TokenType)
		}
		if response.IDTokenRaw != "" && (!compactJOSE.MatchString(response.IDTokenRaw) || len(response.IDTokenRaw) > MaxIDTokenBytes) {
			t.Fatalf("id_token %q", response.IDTokenRaw)
		}
		if response.ExpiresIn < 0 {
			t.Fatalf("expires_in %d", response.ExpiresIn)
		}
		for _, value := range []string{response.TokenType, response.AccessToken, response.RefreshToken, response.Scope} {
			for _, r := range value {
				if r < 0x20 || r > 0x7e || unicode.IsControl(r) {
					t.Fatalf("accepted %q", value)
				}
			}
		}
	})
}
