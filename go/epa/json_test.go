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

package epa

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// The body of an entitle request is the proxy's own format: a member twice, invalid UTF-8, a member it does not know
// and a member in another case are refused, each for its reason.
func TestServerRule28_AnEntitleBodyIsReadStrictly(t *testing.T) {
	for name, test := range map[string]struct {
		body string
		want error
	}{
		"a member twice":      {`{"provider":1,"provider":2}`, jsontext.ErrDuplicateName},
		"another case":        {`{"Provider":1}`, json.ErrUnknownName},
		"an unknown member":   {`{"provider":1,"insurant":"X"}`, json.ErrUnknownName},
		"invalid UTF-8":       {"{\"provider\":1,\"\xff\":2}", nil},
		"larger than a bound": {`{"provider":1}` + strings.Repeat(" ", maxEntitleBodyBytes), nil},
	} {
		_, err := entitleProvider(strings.NewReader(test.body))
		if !errors.Is(err, errEntitleBody) || test.want != nil && !errors.Is(err, test.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := entitleProvider(strings.NewReader("{\"provider\":1,\"\xff\":2}")); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Errorf("invalid UTF-8: %v", err)
	}
	for _, test := range []struct {
		body string
		want ProviderNumber
	}{{``, 0}, {" \r\n", 0}, {`{}`, 0}, {`{"provider":2}`, 2}} {
		if provider, err := entitleProvider(strings.NewReader(test.body)); err != nil || provider != test.want {
			t.Errorf("%q: %d %v", test.body, provider, err)
		}
	}
}

// FuzzEntitleProvider feeds arbitrary bodies to the entitle request's reader. Invariants: it never panics, what it
// accepts is empty or one object naming at most provider, and a refusal is errEntitleBody.
func FuzzEntitleProvider(f *testing.F) {
	for _, seed := range []string{
		``, ` `, `{}`, `{"provider":1}`, `{"provider":"1"}`, `{"provider":1.5}`, `{"provider":1e999}`, `null`, `[]`,
		`{"provider":1,"provider":2}`, `{"Provider":1}`, `{"PROVIDER":1}`, "{\"provider\":1,\"\xff\":2}", `{"provider":1} {}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		_, err := entitleProvider(strings.NewReader(string(body)))
		if err != nil && !errors.Is(err, errEntitleBody) {
			t.Fatalf("refused without errEntitleBody: %v", err)
		}
		if err == nil && len(body) > maxEntitleBodyBytes {
			t.Fatalf("accepted %d bytes", len(body))
		}
	})
}

// An Aktensystem's error answer naming a member twice or carrying invalid UTF-8 is not read as a typed error, and a
// member in another case is not taken for the member: the error then shows the status and the body as text.
func TestServerRule28_AnAktensystemErrorIsReadStrictly(t *testing.T) {
	for name, body := range map[string]string{
		"a member twice": `{"errorCode":"a","errorCode":"b"}`,
		"invalid UTF-8":  "{\"errorCode\":\"a\xffb\"}",
		"another case":   `{"ErrorCode":"a"}`,
	} {
		err := parseHTTPError(&http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(body))})
		var typed *ErrorType
		if errors.As(err, &typed) && typed.ErrorCode != "" {
			t.Errorf("%s: read as %+v", name, typed)
		}
	}
	err := parseHTTPError(&http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(`{"errorCode":"a","errorDetail":"b"}`))})
	var typed *ErrorType
	if !errors.As(err, &typed) || typed.ErrorCode != "a" || typed.ErrorDetail != "b" || typed.HTTPStatusCode != http.StatusForbidden {
		t.Errorf("a well-formed error: %v", err)
	}
}

// FuzzParseHTTPError feeds arbitrary bodies to the reader of an Aktensystem's error answer. Invariants: it never
// panics and always returns an error, and a typed one holds valid UTF-8.
func FuzzParseHTTPError(f *testing.F) {
	for _, seed := range []string{
		`{"errorCode":"a","errorDetail":"b"}`, ``, `null`, `[]`, `{"errorCode":1}`,
		`{"errorCode":"a","errorCode":"b"}`, `{"ErrorCode":"a","ERRORDETAIL":"b"}`, "{\"errorCode\":\"a\xffb\"}",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		err := parseHTTPError(&http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(string(body)))})
		if err == nil {
			t.Fatal("no error")
		}
		var typed *ErrorType
		if errors.As(err, &typed) && (!utf8.ValidString(typed.ErrorCode) || !utf8.ValidString(typed.ErrorDetail)) {
			t.Fatalf("typed error with invalid UTF-8: %q", typed.ErrorCode)
		}
	})
}

// The proxy's answers keep the shape they had: a nil list is null, a provider of zero is left out, and a map's members
// are sorted.
func TestTheProxysAnswersKeepTheirShape(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusOK, &InsurantInfo{InsurantID: "X000000001"})
	const want = `{"insurantId":"X000000001","record":{"found":false},"providers":null,"entitlement":{"entitled":false}}`
	if got := recorder.Body.String(); got != want {
		t.Errorf("wrote %s, want %s", got, want)
	}
	recorder = httptest.NewRecorder()
	writeJSON(recorder, http.StatusCreated, map[string]any{"provider": 1, "insurantId": "X", "entitledAt": "t"})
	if got := recorder.Body.String(); got != `{"entitledAt":"t","insurantId":"X","provider":1}` {
		t.Errorf("wrote %s", got)
	}
}
