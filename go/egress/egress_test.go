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

package egress

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func egressClient(t *testing.T) *http.Client {
	t.Helper()
	client, err := NewClient(5*time.Second, Options{})
	if err != nil {
		t.Skipf("no system roots: %v", err)
	}
	return client
}

func plainServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

// servers.md rule 30: the egress client sends nothing over plain http unless the caller marks the request as
// fetching data that proves itself, and the server is never reached.
func TestServerRule30_TheEgressClientRefusesPlainHTTP(t *testing.T) {
	client := egressClient(t)
	server, hits := plainServer(t, func(http.ResponseWriter, *http.Request) {})
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
	if _, err := client.Do(request); !errors.Is(err, ErrPlainHTTP) {
		t.Fatalf("err = %v, want ErrPlainHTTP", err)
	}
	if hits.Load() != 0 {
		t.Error("the server was reached")
	}
}

// servers.md rule 30: OCSP responses, CRLs and the TSL prove themselves by their signatures and may travel over
// plain http.
func TestServerRule30_SelfVerifyingDataGoesOutOverPlainHTTP(t *testing.T) {
	client := egressClient(t)
	server, hits := plainServer(t, func(http.ResponseWriter, *http.Request) {})
	request, _ := http.NewRequestWithContext(SelfVerifying(t.Context()), http.MethodGet, server.URL, http.NoBody)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}

// servers.md rules 2 and 30: a redirect is a new request held to the same rule, so an https fetch cannot be sent on
// to plain http.
func TestServerRule30_ARedirectToPlainHTTPIsRefused(t *testing.T) {
	client := egressClient(t)
	target, hits := plainServer(t, func(http.ResponseWriter, *http.Request) {})
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(source.Close)
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = source.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	client = &http.Client{Transport: transport, Timeout: client.Timeout}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, source.URL, http.NoBody)
	if _, err := client.Do(request); !errors.Is(err, ErrPlainHTTP) {
		t.Fatalf("err = %v, want ErrPlainHTTP", err)
	}
	if hits.Load() != 0 {
		t.Error("the redirect target was reached")
	}
}

// servers.md rule 30: a library that adds a client certificate clones the transport; the clone keeps the rule.
func TestServerRule30_AClonedEgressTransportKeepsTheRule(t *testing.T) {
	client := egressClient(t)
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &tls.Certificate{}, nil
	}
	server, hits := plainServer(t, func(http.ResponseWriter, *http.Request) {})
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
	if _, err := (&http.Client{Transport: transport}).Do(request); !errors.Is(err, ErrPlainHTTP) {
		t.Fatalf("err = %v, want ErrPlainHTTP", err)
	}
	if hits.Load() != 0 {
		t.Error("the server was reached")
	}
}

// A peer of the deployment the host configured itself may be plain http: NewTransport has no egress rule and no
// forward proxy.
func TestNewTransportReachesAPeerOverPlainHTTP(t *testing.T) {
	transport, err := NewTransport(Options{})
	if err != nil {
		t.Skipf("no system roots: %v", err)
	}
	if transport.Proxy != nil {
		t.Error("the peer transport takes a forward proxy")
	}
	server, hits := plainServer(t, func(http.ResponseWriter, *http.Request) {})
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}
