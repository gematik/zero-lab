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
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
)

// serve starts a TLS server presenting chain with the OCSP response staple; resumed
// counts the handshakes it resumed.
func serve(t *testing.T, chain []*issued, staple []byte) (server *httptest.Server, resumed *atomic.Int64) {
	t.Helper()
	resumed = &atomic.Int64{}
	certificate := tls.Certificate{PrivateKey: chain[0].key, OCSPStaple: staple}
	for _, cert := range chain {
		certificate.Certificate = append(certificate.Certificate, cert.cert.Raw)
	}
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.DidResume {
				resumed.Add(1)
			}
			return nil
		},
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, resumed
}

// client reaches server under host, whatever host resolves to, with config, one connection per request.
func client(server *httptest.Server, config *tls.Config) *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig:   config,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
	}}
}

func get(t *testing.T, c *http.Client, url string) error {
	t.Helper()
	response, err := c.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("body %q, %v", body, err)
	}
	return nil
}

// TLSV-040 to 044 over a real handshake: a server with a P-256 chain under the test's root and a stapled
// OCSP response is accepted by the web configuration, as net/http uses it.
func TestTLSV040AWebServerIsAcceptedOverAHandshake(t *testing.T) {
	now := time.Now()
	root := issue(t, caTemplate("TLSV Web Root TEST-ONLY", now.Add(-time.Hour)), nil)
	ca := issue(t, caTemplate("TLSV Web CA TEST-ONLY", now.Add(-time.Hour)), root)
	leaf := issue(t, serverTemplate("www.web.test", now.Add(-time.Hour)), ca)
	server, _ := serve(t, []*issued{leaf, ca}, goodOCSP(t, leaf.cert, ca, now.Add(-time.Minute), false))

	verifier := NewWebVerifier(NewWebCheck([]*x509.Certificate{root.cert}), Offline{}, Options{})
	if err := get(t, client(server, verifier.ClientConfig()), "https://www.web.test/"); err != nil {
		t.Fatal(err)
	}
	if verifier.verdicts.size() != 1 {
		t.Fatalf("%d verdicts kept", verifier.verdicts.size())
	}
	err := get(t, client(server, verifier.ClientConfig()), "https://other.web.test/")
	if err == nil {
		t.Fatal("a host the certificate does not name is accepted")
	}

	// Without the staple, and with every revocation source down, the same server is accepted with a warning
	// and its verdict not kept (TLSV-044, TLSV-050).
	bare, _ := serve(t, []*issued{leaf, ca}, nil)
	offline := NewWebVerifier(NewWebCheck([]*x509.Certificate{root.cert}), Offline{}, Options{})
	if err := get(t, client(bare, offline.ClientConfig()), "https://www.web.test/"); err != nil {
		t.Fatalf("without a status: %v", err)
	}
	if offline.verdicts.size() != 0 {
		t.Fatalf("without a status, %d verdicts kept", offline.verdicts.size())
	}
}

// TLSV-040 and TLSV-045: httptest's default certificate is refused, by crypto/tls under roots that do not
// hold it, and by the profile's rules under roots that do: it is valid for decades. Its RSA 2048 key alone
// would be accepted with a warning (TLSV-041).
func TestTLSV045HttptestsDefaultCertificateIsRefused(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)

	if err := get(t, client(server, webCorpusVerifierConfig(t)), "https://example.com/"); err == nil {
		t.Fatal("accepted under roots that do not hold it")
	}
	own := NewWebVerifier(NewWebCheck([]*x509.Certificate{server.Certificate()}), Offline{}, Options{}).ClientConfig()
	err := get(t, client(server, own), "https://example.com/")
	if refused, ok := errors.AsType[*RefusedError](err); !ok || refused.Verdict.Code != ValidityTooLong {
		t.Fatalf("under its own root: %v", err)
	}
}

func webCorpusVerifierConfig(t *testing.T) *tls.Config {
	t.Helper()
	return NewWebVerifier(webCorpusCheck(t), Offline{}, Options{}).ClientConfig()
}

// tiServer is a TI server as the TSL would back it: a root, a CA listed for C.FD.TLS-S, and a C.FD.TLS-S
// end entity on P-256, as ePA's are, stapling a response with the TI's certHash.
func tiServer(t *testing.T) (*httptest.Server, *atomic.Int64, *tipki.TrustStore) {
	t.Helper()
	now := time.Now()
	root := issue(t, caTemplate("GEM.RCA90 TEST-ONLY", now.Add(-time.Hour)), nil)
	ca := issue(t, caTemplate("GEM.KOMP-CA90 TEST-ONLY", now.Add(-time.Hour)), root)
	template := serverTemplate("svc.ti.test", now.Add(-time.Hour))
	template.Policies = []x509.OID{
		mustOID(t, "1.2.276.0.76.4.163"),
		tipki.CertFdTLSS.OID(),
	}
	leaf := issue(t, template, ca)
	server, resumed := serve(t, []*issued{leaf, ca}, goodOCSP(t, leaf.cert, ca, now.Add(-time.Minute), true))
	store := &tipki.TrustStore{
		Roots:         []*x509.Certificate{root.cert},
		Intermediates: []tipki.Intermediate{{Certificate: ca.cert, Provider: "TEST-ONLY"}},
		CATypes:       map[string][]x509.OID{string(ca.cert.Raw): {tipki.CertFdTLSS.OID()}},
	}
	return server, resumed, store
}

func mustOID(t *testing.T, text string) x509.OID {
	t.Helper()
	oid, err := x509.ParseOID(text)
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

// TLSV-030 to 033 over a real handshake: a ti server is accepted through tipki's check, though crypto/tls
// does not verify it; another host and withdrawn trust material are refused.
func TestTLSV030ATiServerIsAcceptedOverAHandshake(t *testing.T) {
	server, _, store := tiServer(t)
	source := NewTrustSource(store)
	config := NewTiVerifier(source, nil, Options{}).ClientConfig()

	if err := get(t, client(server, config), "https://svc.ti.test/"); err != nil {
		t.Fatal(err)
	}
	err := get(t, client(server, config), "https://other.ti.test/")
	if refused, ok := errors.AsType[*RefusedError](err); !ok || refused.Verdict.Code != NameMismatch {
		t.Fatalf("another host: %v", err)
	}
	source.Swap(nil)
	err = get(t, client(server, config), "https://svc.ti.test/")
	if refused, ok := errors.AsType[*RefusedError](err); !ok || refused.Verdict.Code != TrustMaterialUnavailable {
		t.Fatalf("withdrawn trust material: %v", err)
	}
	if err := get(t, client(server, NewTiVerifier(NewTrustSource(&tipki.TrustStore{}), nil, Options{}).ClientConfig()), "https://svc.ti.test/"); err == nil {
		t.Fatal("accepted under trust material without its CA")
	}
}

// TLSV-014 and TLSV-050: a host that adds a session cache resumes, and a resumed handshake is checked as a
// full one is: after the trust material is withdrawn, resumption is refused.
func TestTLSV014AResumedHandshakeIsCheckedAgain(t *testing.T) {
	server, resumed, store := tiServer(t)
	source := NewTrustSource(store)
	config := NewTiVerifier(source, nil, Options{}).ClientConfig()
	config.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	c := client(server, config)

	for range 2 {
		if err := get(t, c, "https://svc.ti.test/"); err != nil {
			t.Fatal(err)
		}
	}
	if resumed.Load() == 0 {
		t.Fatal("the second connection did not resume")
	}
	before := resumed.Load()
	source.Swap(nil)
	err := get(t, c, "https://svc.ti.test/")
	if refused, ok := errors.AsType[*RefusedError](err); !ok || refused.Verdict.Code != TrustMaterialUnavailable {
		t.Fatalf("resumed after withdrawal: %v", err)
	}
	if resumed.Load() == before {
		t.Fatal("the refused connection was not a resumption")
	}
}
