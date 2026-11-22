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

package cmd

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// Server rule 28, "Headers" and "Method and path": a request to a foreign Host gets 421 and one with a
// non-canonical path 400, before the router sees either.
func TestServerRule28_AForeignHostOrANonCanonicalPathIsRefused(t *testing.T) {
	reached := false
	handler := guard([]string{"localhost:8082", "epa.example"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	for _, c := range []struct {
		host, target string
		want         int
	}{
		{"localhost:8082", "/api/providers", http.StatusOK},
		{"epa.example", "/api/providers", http.StatusOK},
		{"evil.example", "/api/providers", http.StatusMisdirectedRequest},
		{"LOCALHOST:8082", "/api/providers", http.StatusMisdirectedRequest},
		{"localhost:8083", "/api/providers", http.StatusMisdirectedRequest},
		{"localhost:8082", "/api/x/../providers", http.StatusBadRequest},
		{"localhost:8082", "/api/x/%2e%2e/providers", http.StatusBadRequest},
		{"localhost:8082", "/api%2Fproviders", http.StatusBadRequest},
	} {
		reached = false
		req := httptest.NewRequest(http.MethodGet, c.target, nil)
		req.Host = c.host
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != c.want || reached != (c.want == http.StatusOK) {
			t.Errorf("Host %q, %s: %d, reached %v; want %d", c.host, c.target, rec.Code, reached, c.want)
		}
	}
}

// Without configured names the server answers to the loopback names of its port only.
func TestServerRule28_TheHostNamesDefaultToTheLoopbackNames(t *testing.T) {
	for _, c := range []struct {
		addr       string
		configured []string
		want       []string
	}{
		{":8082", nil, []string{"localhost:8082", "127.0.0.1:8082", "[::1]:8082"}},
		{"0.0.0.0:9", nil, []string{"localhost:9", "127.0.0.1:9", "[::1]:9"}},
		{"127.0.0.1:9", nil, []string{"127.0.0.1:9"}},
		{":8082", []string{"epa.example"}, []string{"epa.example"}},
	} {
		got, err := hostNames(c.addr, c.configured)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("hostNames(%q, %v) = %v, %v", c.addr, c.configured, got, err)
		}
	}
	if _, err := hostNames("8082", nil); err == nil {
		t.Error("an address without port gave names")
	}
}
