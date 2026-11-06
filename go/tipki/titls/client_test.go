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

package titls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TLSV-001 and TLSV-040: the host's internet client verifies under the web profile against the system's
// roots, so a server whose root the system does not hold is refused before a request is sent (TLSV-002).
func TestTLSV040TheWebHTTPClientRefusesAnUnknownIssuer(t *testing.T) {
	client, err := NewWebHTTPClient(5*time.Second, Options{})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == http.DefaultTransport {
		t.Fatalf("transport %T is not a copy of the default transport", client.Transport)
	}
	config := transport.TLSClientConfig
	if config == nil || config.VerifyConnection == nil || config.InsecureSkipVerify || config.RootCAs == nil {
		t.Fatalf("the transport does not verify under the web profile: %+v", config)
	}
	if config.MinVersion != tls.VersionTLS12 || !transport.ForceAttemptHTTP2 || client.Timeout != 5*time.Second {
		t.Errorf("MinVersion %#04x, ForceAttemptHTTP2 %v, timeout %v", config.MinVersion, transport.ForceAttemptHTTP2, client.Timeout)
	}

	var reached atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}

	response, err := client.Get("https://example.com/")
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("a server under httptest's own root is accepted")
	}
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
		t.Errorf("not refused for its certificate: %v", err)
	}
	if reached.Load() {
		t.Error("the request reached the server")
	}
}
