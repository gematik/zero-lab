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
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// marker stands for an Aktensystem's or a client's input; an error that holds it would carry that input into a log
// or an answer (servers.md rule 14).
const marker = "PEER-INPUT-7f3a"

// Server rule 14: an Aktensystem's error answer, typed or not, is named by its status; the body, its errorCode and its
// errorDetail stay out of the error text, and the typed fields still hold what the Aktensystem said.
func TestServerRule14_AnAktensystemErrorIsNotQuoted(t *testing.T) {
	for name, body := range map[string]string{
		"a typed error":  `{"errorCode":"` + marker + `","errorDetail":"` + marker + `"}`,
		"text":           "Fehler: " + marker,
		"a member twice": `{"errorCode":"a","` + marker + `":1,"` + marker + `":2}`,
	} {
		err := parseHTTPError(&http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(body))})
		if err == nil || strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "403") {
			t.Errorf("%s: %v", name, err)
		}
	}
	err := parseHTTPError(&http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(`{"errorCode":"` + marker + `"}`))})
	var typed *ErrorType
	if !errors.As(err, &typed) || typed.ErrorCode != marker {
		t.Errorf("the typed error lost its code: %v", err)
	}
}

// Server rule 14: an Aktensystem's answer that does not decode is named, not quoted: the decoder's message would
// carry a member's name. The decoder's reason still unwraps.
func TestServerRule14_AnUndecodableAnswerIsNotQuoted(t *testing.T) {
	aktensystem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"`+marker+`":1,"`+marker+`":2}`)
	}))
	defer aktensystem.Close()
	client := &Client{BaseURL: aktensystem.URL, HTTPClient: aktensystem.Client()}
	_, err := client.GetConsentDecisionInformation("X000000001")
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("got %v, want a refusal without the member's name", err)
	}
	if !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Errorf("got %v, want a duplicate name to unwrap", err)
	}
}

// Server rule 14: a refused entitle body is named, not quoted, though the reason still unwraps.
func TestServerRule14_ARefusedEntitleBodyIsNotQuoted(t *testing.T) {
	for _, body := range []string{
		`{"` + marker + `":1}`,
		`{"provider":1,"` + marker + `":1,"` + marker + `":2}`,
		`{"provider":"` + marker + `"}`,
	} {
		_, err := entitleProvider(strings.NewReader(body))
		if !errors.Is(err, errEntitleBody) || strings.Contains(err.Error(), marker) {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// Server rule 14: when no Aktensystem holds the record, the answer and the log do not name the KVNR, which is
// personal data, and an Aktensystem's error body reaches neither.
func TestServerRule14_ARecordSearchDoesNotNameTheKVNR(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	const kvnr = "X123456789"
	var calls atomic.Int32
	aktensystem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1)%2 == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, marker)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer aktensystem.Close()
	p := &Proxy{
		sessionManager: &sessionManager{
			sessions: map[ProviderNumber]*Session{},
			login: func(provider ProviderNumber) (*Session, error) {
				return &Session{Client: &Client{ProviderNumber: provider, BaseURL: aktensystem.URL, HTTPClient: aktensystem.Client()}}, nil
			},
		},
	}
	_, err := p.findRecordProvider(kvnr)
	if err == nil {
		t.Fatal("a record was found")
	}
	for _, text := range []string{err.Error(), logs.String()} {
		if strings.Contains(text, kvnr) || strings.Contains(text, marker) {
			t.Errorf("names the KVNR or quotes the Aktensystem: %s", text)
		}
	}
}
