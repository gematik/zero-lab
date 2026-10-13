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

package bff_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gematik/zero-lab/go/bff"
	"github.com/gematik/zero-lab/go/kv"
)

// Protect treats the cookie value as an opaque session id and looks it up in the SessionManager; the
// session is authorized only once it carries an access token.
func TestGuardSessionCookie(t *testing.T) {
	sm := bff.NewSessionManager(kv.NewMemory(), 0)
	session, err := sm.CreateSession("state", "verifier", "S256")
	if err != nil {
		t.Fatal(err)
	}
	session.AccessToken = "an-access-token"
	if err := sm.UpdateSession(session); err != nil {
		t.Fatal(err)
	}

	b := newTestBFF(t, sm)
	protected := b.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s, ok := bff.SessionFromContext(r.Context()); !ok || s.ID != session.ID {
			t.Errorf("protected handler: session not in context")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("You are in"))
	}))

	do := func(cookieValue string) int {
		req := httptest.NewRequest("GET", "/protected", nil)
		if cookieValue != "" {
			req.AddCookie(&http.Cookie{Name: "test-cookie", Value: cookieValue})
		}
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(session.ID); code != http.StatusOK {
		t.Fatalf("valid session: expected %d, got %d", http.StatusOK, code)
	}
	if code := do("nonexistent-session-id"); code != http.StatusUnauthorized {
		t.Fatalf("unknown session: expected %d, got %d", http.StatusUnauthorized, code)
	}
}
