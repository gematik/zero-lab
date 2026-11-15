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

package main

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestIndexAnswersBrowsersWithHTMLAndProgramsWithJSON shows the smoke test's two readers at GET /: a browser's
// Accept gets the page, curl's and a program's get the info document, and both answers say they vary by Accept.
func TestIndexAnswersBrowsersWithHTMLAndProgramsWithJSON(t *testing.T) {
	cases := []struct {
		name, accept, contentType string
	}{
		{"browser", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html"},
		{"curl", "*/*", "application/json"},
		{"no accept", "", "application/json"},
		{"program", "application/json", "application/json"},
		{"html refused", "text/html;q=0, */*", "application/json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.accept != "" {
				r.Header.Set("Accept", c.accept)
			}
			w := httptest.NewRecorder()
			handleIndex(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d", w.Code)
			}
			if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, c.contentType) {
				t.Fatalf("Content-Type %q, want %s", got, c.contentType)
			}
			if got := w.Header().Get("Vary"); got != "Accept" {
				t.Fatalf("Vary %q, want Accept", got)
			}
			if c.contentType == "application/json" {
				var doc map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				if doc["app"] != "metsubushi" {
					t.Fatalf("app %v, want metsubushi", doc["app"])
				}
			}
		})
	}
}
