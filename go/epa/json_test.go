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
		"larger than a bound": {`{"provider":1}` + strings.Repeat(" ", maxEntitleBodyBytes), errEntitleBodyTooLarge},
	} {
		_, err := entitleProvider(strings.NewReader(test.body))
		if !errors.Is(err, errEntitleBody) || test.want != nil && !errors.Is(err, test.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var syntactic *jsontext.SyntacticError
	if _, err := entitleProvider(strings.NewReader("{\"provider\":1,\"\xff\":2}")); !errors.As(err, &syntactic) || !strings.Contains(syntactic.Error(), "invalid UTF-8") {
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
// member in another case is not taken for the member: the error then holds the status alone.
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
// panics and always returns an error, its text is valid UTF-8, and a typed one holds valid UTF-8.
func FuzzParseHTTPError(f *testing.F) {
	for _, seed := range []string{
		`{"errorCode":"a","errorDetail":"b"}`, ``, `null`, `[]`, `{"errorCode":1}`,
		`{"errorCode":"a","errorCode":"b"}`, `{"ErrorCode":"a","ERRORDETAIL":"b"}`, "{\"errorCode\":\"a\xffb\"}", "Gr\xfc\xdfe",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		err := parseHTTPError(&http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(string(body)))})
		if err == nil {
			t.Fatal("no error")
		}
		if !utf8.ValidString(err.Error()) {
			t.Fatalf("error text with invalid UTF-8: %q", err.Error())
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
	const want = `{"insurantId":"X000000001","record":{"found":false},"providers":null,"entitlement":{"entitled":false}}` + "\n"
	if got := recorder.Body.String(); got != want {
		t.Errorf("wrote %s, want %s", got, want)
	}
	recorder = httptest.NewRecorder()
	writeJSON(recorder, http.StatusCreated, map[string]any{"provider": 1, "insurantId": "X", "entitledAt": "t"})
	if got := recorder.Body.String(); got != `{"entitledAt":"t","insurantId":"X","provider":1}`+"\n" {
		t.Errorf("wrote %s", got)
	}
}

// An Aktensystem's error answer that is not UTF-8, here Latin-1, still leaves the proxy a complete JSON answer with
// its status, both for the insurant's information and on the way into the VAU. The body itself is not passed on
// (servers.md rule 14).
func TestAnAktensystemErrorInLatin1KeepsTheAnswerJSON(t *testing.T) {
	aktensystem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "Aktensystem nicht erreichbar: Gr\xfc\xdfe, \xe4")
	}))
	defer aktensystem.Close()
	p := &Proxy{
		records: map[string]PatientRecordMetadata{},
		sessionManager: &sessionManager{
			sessions: map[ProviderNumber]*Session{},
			login: func(provider ProviderNumber) (*Session, error) {
				return &Session{Client: &Client{ProviderNumber: provider, BaseURL: aktensystem.URL, HTTPClient: aktensystem.Client()}}, nil
			},
		},
	}
	for name, handle := range map[string]http.HandlerFunc{
		"GET /insurants/{insurantID}": p.HandleInsurantInfo,
		"into the VAU":                p.HandleForwardToVAUInsurant,
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetPathValue("insurantID", "X000000001")
		req.SetPathValue("path", "x")
		recorder := httptest.NewRecorder()
		handle(recorder, req)
		body := recorder.Body.Bytes()
		var answer MultiProviderError
		if recorder.Code != http.StatusBadGateway || !strings.HasSuffix(string(body), "\n") || json.Unmarshal(body, &answer) != nil {
			t.Errorf("%s: %d %q", name, recorder.Code, body)
			continue
		}
		if len(answer.Errors) != len(AllProviders) || !strings.Contains(answer.Errors[0].Description, "500") ||
			strings.Contains(answer.Errors[0].Description, "erreichbar") {
			t.Errorf("%s: %+v", name, answer)
		}
	}
}
