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
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/bff"
	"github.com/gematik/zero-lab/go/kv"
)

// Servers rule 5: logs carry no tokens or secrets. The session ID is the cookie's value and the
// state guards the login, so neither appears in a log line or in an error a caller may log.
func TestServersRule5_SessionIDAndStateNeverLogged(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	sm := bff.NewSessionManager(kv.NewMemory(), 0)
	state := "state-that-must-not-be-logged"
	session, err := sm.CreateSession(state, "verifier", "S256")
	if err != nil {
		t.Fatal(err)
	}
	if err := sm.UpdateSession(session); err != nil {
		t.Fatal(err)
	}
	if err := sm.DeleteSessionByID(session.ID); err != nil {
		t.Fatal(err)
	}
	_, errByID := sm.GetSessionByID(session.ID)
	_, errByState := sm.GetSessionByState(state)
	if errByID == nil || errByState == nil {
		t.Fatal("deleted session still found")
	}

	if logs.Len() == 0 {
		t.Fatal("no log lines captured; the check would pass vacuously")
	}
	for _, where := range []string{logs.String(), errByID.Error(), errByState.Error()} {
		for _, secret := range []string{session.ID, state} {
			if strings.Contains(where, secret) {
				t.Errorf("%q leaks %q", where, secret)
			}
		}
	}
}
