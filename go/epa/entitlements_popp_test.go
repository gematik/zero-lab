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
package epa_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/epa/vau"
)

// A_27671: the PoPP token is single-use. A refused entitlement is not sent again with the same token, and
// the token appears in no log line.
func TestA_27671_APoPPTokenIsSentOnceAndNeverLogged(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	server, err := vau.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	var nested atomic.Int32
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") == "application/octet-stream" {
			nested.Add(1)
		}
		server.ServeHTTP(w, r)
	}))
	t.Cleanup(stub.Close)
	channel, err := vau.OpenChannel(stub.URL, vau.EnvNonPU, stub.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := offlineSession(t, &epa.SecurityFunctions{})
	session.VAUChannel = channel

	const token = "popp-token-header.popp-token-claims.popp-token-signature"
	// The test server answers every request with 200, never with the 201 of a registered entitlement.
	if _, err := session.SetEntitlementPoPP("X110600196", token); err == nil {
		t.Fatal("a refused entitlement went unnoticed")
	} else if strings.Contains(err.Error(), token) {
		t.Errorf("the error holds the token: %v", err)
	}
	if got := nested.Load(); got != 1 {
		t.Errorf("the entitlement was sent %d times", got)
	}
	if strings.Contains(logs.String(), token) {
		t.Errorf("the log holds the token:\n%s", logs.String())
	}
}
