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

package authzserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOAuthErrorNormalizer verifies that ALL error responses — including ServeMux's
// framework-level 404 (unknown path) and 405 (wrong method) — are rendered in the
// OAuth 2.0 JSON error shape, while 2xx and handler-written JSON pass through unchanged.
func TestOAuthErrorNormalizer(t *testing.T) {
	mux := http.NewServeMux()
	// a normal JSON 200 handler
	mux.HandleFunc("GET /ok", func(w http.ResponseWriter, r *http.Request) {
		_ = writeJSON(w, http.StatusOK, map[string]string{"hello": "world"})
	})
	// a handler that returns an OAuth error via the handle adapter
	s := &Server{}
	mux.Handle("POST /thing", s.handle(func(w http.ResponseWriter, r *http.Request) error {
		return &Error{HttpStatus: http.StatusBadRequest, Code: "invalid_request", Description: "nope"}
	}))

	srv := OAuthErrors(Logger(Recover(mux)))

	type tc struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantCode   string // expected OAuth "error" code; "" means non-error JSON passthrough
	}
	cases := []tc{
		{"ok passthrough", "GET", "/ok", http.StatusOK, ""},
		{"handler oauth error", "POST", "/thing", http.StatusBadRequest, "invalid_request"},
		{"unknown path 404", "GET", "/does-not-exist", http.StatusNotFound, "not_found"},
		{"wrong method 405", "GET", "/thing", http.StatusMethodNotAllowed, "method_not_allowed"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, nil)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content-type = %q, want application/json", ct)
			}
			if c.wantCode == "" {
				return // non-error passthrough, body shape not asserted
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not JSON: %v (body=%q)", err, rec.Body.String())
			}
			if body.Error != c.wantCode {
				t.Fatalf("error = %q, want %q", body.Error, c.wantCode)
			}
		})
	}
}
