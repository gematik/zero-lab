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

package idpd

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TLSV-001: the host decides TLS. The client is a constructor parameter, so the compiler holds every
// caller to passing one; a nil one builds neither an authenticator nor a client and sends nothing, and a
// host's client is used as given.
func TestTLSV001ANilClientIsRefusedAndNothingReachesTheIDPDienst(t *testing.T) {
	var reached atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)

	_, err := NewAuthenticator(AuthenticatorConfig{IDP: NewIDP(EnvironmentReference, server.URL), Trust: &recording{}}, nil)
	if !errors.Is(err, errNoHTTPClient) {
		t.Errorf("authenticator: %v", err)
	}
	_, err = NewClientFromConfig(ClientConfig{
		Environment: EnvironmentReference, BaseURL: server.URL, ClientID: "client", RedirectURI: "https://rp.example/cb",
		Scopes: []string{"openid"}, Trust: &recording{},
	}, nil)
	if !errors.Is(err, errNoHTTPClient) {
		t.Errorf("client: %v", err)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("%d requests reached the server", n)
	}

	_, err = NewAuthenticator(AuthenticatorConfig{IDP: NewIDP(EnvironmentReference, server.URL), Trust: &recording{}}, server.Client())
	if err == nil || reached.Load() != 1 {
		t.Fatalf("the host's client was not used: %v, %d requests", err, reached.Load())
	}
}
