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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"maps"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fromMap(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

func TestServerRule29_AListenerURLIsRequiredAndPEP_ADDRIsRetired(t *testing.T) {
	for name, vars := range map[string]map[string]string{
		"nothing set": {},
		"PEP_ADDR":    {"PEP_ADDR": ":4180"},
		"both":        {"PEP_ADDR": ":4180", "PEP_LISTEN_URL": "http://127.0.0.1:4180"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := listenFromEnv(fromMap(vars), time.Now()); err == nil {
				t.Error("started")
			}
		})
	}
}

// servers.md rule 29: plaintext outside the pod only once the operator accepts it, with exactly "true".
func TestServerRule29_PlaintextOutsideThePodNeedsTheOperatorsAcceptance(t *testing.T) {
	for value, starts := range map[string]bool{"": false, "true": true, "false": false, "yes": false, "TRUE": false} {
		t.Run("accepted="+value, func(t *testing.T) {
			spec, err := listenFromEnv(fromMap(map[string]string{"PEP_LISTEN_URL": "http://0.0.0.0:4180", "PEP_LISTEN_PLAINTEXT_ACCEPTED": value}), time.Now())
			if (err == nil) != starts {
				t.Fatalf("err = %v, want start %v", err, starts)
			}
			if starts && (spec.tls != nil || spec.address != "0.0.0.0:4180" || !strings.Contains(spec.mode, "accepted")) {
				t.Errorf("spec = %+v", spec)
			}
		})
	}
}

// servers.md rule 29: a loopback address stays inside the pod like a Unix socket and needs no acceptance; an
// acceptance there accepts nothing and is refused.
func TestServerRule29_LoopbackIsInsideThePod(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:4180", "http://[::1]:4180", "http://127.0.0.2:4180"} {
		if _, err := listenFromEnv(fromMap(map[string]string{"PEP_LISTEN_URL": raw}), time.Now()); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
		if _, err := listenFromEnv(fromMap(map[string]string{"PEP_LISTEN_URL": raw, "PEP_LISTEN_PLAINTEXT_ACCEPTED": "true"}), time.Now()); err == nil {
			t.Errorf("%s: an acceptance on loopback was taken", raw)
		}
	}
}

// servers.md rules 17 and 29: the URL names a scheme, an address and a port, and nothing else; the public name is
// PEP_PUBLIC_URL's.
func TestServerRule29_AListenerURLBindsAnAddressAndAPortOnly(t *testing.T) {
	for _, raw := range []string{
		"http://localhost:4180", "http://pep.example:4180", "http://127.0.0.1", "127.0.0.1:4180", ":4180",
		"http://127.0.0.1:4180/path", "http://user@127.0.0.1:4180", "http://127.0.0.1:4180?x=1",
		"unix:///run/pep.sock", "ftp://127.0.0.1:4180",
	} {
		if _, err := listenFromEnv(fromMap(map[string]string{"PEP_LISTEN_URL": raw, "PEP_LISTEN_PLAINTEXT_ACCEPTED": "true"}), time.Now()); err == nil {
			t.Errorf("%s was taken", raw)
		}
	}
	if spec, err := listenFromEnv(fromMap(map[string]string{"PEP_LISTEN_URL": "http://:4180", "PEP_LISTEN_PLAINTEXT_ACCEPTED": "true"}), time.Now()); err != nil || spec.address != ":4180" {
		t.Errorf("every interface: %+v, %v", spec, err)
	}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key}
}

// issue writes a certificate for dns or uri, valid from notBefore for an hour, and its key to dir; it returns their
// paths and the pair.
func (ca *testCA) issue(t *testing.T, dir, name, dns, uri string, notBefore time.Time) (string, string, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: notBefore, NotAfter: notBefore.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if dns != "" {
		template.DNSNames = []string{dns}
	}
	if uri != "" {
		parsed, _ := url.Parse(uri)
		template.URIs = []*url.URL{parsed}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, pair
}

func (ca *testCA) writeBundle(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// servers.md rules 8, 17 and 29: https needs the server's certificate and key; one that does not match its key or
// is not valid now stops the start, and an acceptance of plaintext beside https is refused.
func TestServerRule29_HTTPSStartsOnlyWithAValidMatchingCertificate(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	cert, key, _ := ca.issue(t, dir, "server", "pep.test", "", time.Now().Add(-time.Minute))
	_, otherKey, _ := ca.issue(t, dir, "other", "pep.test", "", time.Now().Add(-time.Minute))
	expired, expiredKey, _ := ca.issue(t, dir, "expired", "pep.test", "", time.Now().Add(-2*time.Hour))
	base := map[string]string{"PEP_LISTEN_URL": "https://0.0.0.0:4443"}
	with := func(more map[string]string) map[string]string {
		vars := maps.Clone(base)
		maps.Copy(vars, more)
		return vars
	}
	if spec, err := listenFromEnv(fromMap(with(map[string]string{"PEP_LISTEN_TLS_CERT_PATH": cert, "PEP_LISTEN_TLS_KEY_PATH": key})), time.Now()); err != nil || spec.tls == nil || spec.mode != "https" {
		t.Fatalf("a valid pair: %+v, %v", spec, err)
	}
	for name, vars := range map[string]map[string]string{
		"no certificate":       {},
		"no key":               {"PEP_LISTEN_TLS_CERT_PATH": cert},
		"another key":          {"PEP_LISTEN_TLS_CERT_PATH": cert, "PEP_LISTEN_TLS_KEY_PATH": otherKey},
		"expired":              {"PEP_LISTEN_TLS_CERT_PATH": expired, "PEP_LISTEN_TLS_KEY_PATH": expiredKey},
		"plaintext accepted":   {"PEP_LISTEN_TLS_CERT_PATH": cert, "PEP_LISTEN_TLS_KEY_PATH": key, "PEP_LISTEN_PLAINTEXT_ACCEPTED": "true"},
		"CA without allowlist": {"PEP_LISTEN_TLS_CERT_PATH": cert, "PEP_LISTEN_TLS_KEY_PATH": key, "PEP_LISTEN_TLS_CA_PATH": ca.writeBundle(t, dir)},
		"allowlist without CA": {"PEP_LISTEN_TLS_CERT_PATH": cert, "PEP_LISTEN_TLS_KEY_PATH": key, "PEP_LISTEN_TLS_PEER_NAME": "spiffe://zeta/edge"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := listenFromEnv(fromMap(with(vars)), time.Now()); err == nil {
				t.Error("started")
			}
		})
	}
}

// dial runs a handshake against address with clientCert (none when nil) and reports whether the server took it:
// under TLS 1.3 the client finishes before the server has judged its certificate, so a read shows the verdict.
func dial(t *testing.T, address string, ca *testCA, clientCert *tls.Certificate) error {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	config := &tls.Config{RootCAs: pool, ServerName: "pep.test", MinVersion: tls.VersionTLS12}
	if clientCert != nil {
		config.Certificates = []tls.Certificate{*clientCert}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, config)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: pep.test\r\n\r\n")); err != nil {
		return err
	}
	_, err = conn.Read(make([]byte, 1))
	return err
}

// servers.md rule 29: identity is pinned, not only chained: under mutual TLS a client of the shared CA is admitted
// only with an identity of the allowlist, and one without a certificate not at all.
func TestServerRule29_MutualTLSAdmitsTheAllowlistAndNobodyElse(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	cert, key, _ := ca.issue(t, dir, "server", "pep.test", "", time.Now().Add(-time.Minute))
	spec, err := listenFromEnv(fromMap(map[string]string{
		"PEP_LISTEN_URL": "https://127.0.0.1:0", "PEP_LISTEN_TLS_CERT_PATH": cert, "PEP_LISTEN_TLS_KEY_PATH": key,
		"PEP_LISTEN_TLS_CA_PATH": ca.writeBundle(t, dir), "PEP_LISTEN_TLS_PEER_NAME": "spiffe://zeta/edge, edge.test",
	}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listen(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := newHTTPServer(nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	_, _, edge := ca.issue(t, dir, "edge", "", "spiffe://zeta/edge", time.Now().Add(-time.Minute))
	_, _, edgeByName := ca.issue(t, dir, "edge-dns", "edge.test", "", time.Now().Add(-time.Minute))
	_, _, stranger := ca.issue(t, dir, "stranger", "", "spiffe://zeta/stranger", time.Now().Add(-time.Minute))
	address := ln.Addr().String()
	if err := dial(t, address, ca, &edge); err != nil {
		t.Errorf("the allowlisted URI was refused: %v", err)
	}
	if err := dial(t, address, ca, &edgeByName); err != nil {
		t.Errorf("the allowlisted DNS name was refused: %v", err)
	}
	if err := dial(t, address, ca, &stranger); err == nil {
		t.Error("an identity outside the allowlist was admitted")
	}
	if err := dial(t, address, ca, nil); err == nil {
		t.Error("a client without a certificate was admitted")
	}
}
