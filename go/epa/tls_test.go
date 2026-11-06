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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/epa/epatest"
	"github.com/gematik/zero-lab/go/tipki/titls"
)

// aktensystem is a TLS server standing in for every Aktensystem: base dials it whatever the host, so the
// client's own URL and server name are used. reached counts the requests that got through.
func aktensystem(t *testing.T) (server *httptest.Server, base *http.Client, reached *atomic.Int64) {
	t.Helper()
	reached = &atomic.Int64{}
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	base = &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
	}}
	return server, base, reached
}

func recordStatus(t *testing.T, base *http.Client, config *tls.Config) error {
	t.Helper()
	client, err := epa.NewClient(epa.EnvDev, epa.ProviderNumber1, &epa.SecurityFunctions{},
		epa.WithHTTPClient(base), epa.WithTLSConfig(config), epa.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.GetRecordStatus("X110600196")
	return err
}

// TASK-229, TLSV-002: no zero-epa path reaches an Aktensystem whose certificate its configuration does not
// trust. The request is not sent, under roots that do not hold the server's certificate as under the ti
// profile without trust material; the server is reached once it is trusted.
func TestTLSV002AnAktensystemWhoseCertificateIsNotTrustedIsNotReached(t *testing.T) {
	server, base, reached := aktensystem(t)

	err := recordStatus(t, base, &tls.Config{RootCAs: x509.NewCertPool()})
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
		t.Errorf("under roots without the server's: %v", err)
	}

	ti := titls.NewTiVerifier(titls.NewTrustSource(nil), nil, titls.Options{}).ClientConfig()
	err = recordStatus(t, base, ti)
	if refused, ok := errors.AsType[*titls.RefusedError](err); !ok || refused.Verdict.Code != titls.TrustMaterialUnavailable {
		t.Errorf("under the ti profile without trust material: %v", err)
	}

	if n := reached.Load(); n != 0 {
		t.Fatalf("%d requests reached the server", n)
	}

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	if err := recordStatus(t, base, &tls.Config{RootCAs: roots, ServerName: "example.com"}); err != nil {
		t.Fatalf("trusted: %v", err)
	}
	if reached.Load() != 1 {
		t.Fatal("the trusted server was not reached")
	}
}

// TLSV-001: an Aktensystem is reached only under a configured verification; without one there is no
// client and no proxy.
func TestTLSV001NoClientOrProxyWithoutTLSVerification(t *testing.T) {
	_, err := epa.NewClient(epa.EnvDev, epa.ProviderNumber1, &epa.SecurityFunctions{})
	if err == nil || !strings.Contains(err.Error(), "no TLS verification configured") {
		t.Errorf("client: %v", err)
	}
	sf := &epa.SecurityFunctions{Identity: &epatest.Identity{SubjectDN: "CN=Test"}}
	proxy, err := epa.NewProxyWithSecurityFunctions(epa.EnvDev, sf, &epatest.Authenticator{Code: "c"}, "test", 5*time.Second, nil)
	if err == nil || !strings.Contains(err.Error(), "no TLS verification configured") {
		t.Errorf("proxy: %v", err)
	}
	if proxy != nil {
		proxy.Close()
	}
}
