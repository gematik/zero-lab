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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// forwardProxy is a test proxy that records what it is asked: a CONNECT tunnels to its target, any other request is
// forwarded.
type forwardProxy struct {
	*httptest.Server
	mu        sync.Mutex
	connects  []string
	forwarded []string
	auth      []string
	// intercept, when set, is where a CONNECT really leads: a server of the proxy's own that terminates TLS.
	intercept string
}

func newForwardProxy(t *testing.T) *forwardProxy {
	t.Helper()
	p := &forwardProxy{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.auth = append(p.auth, r.Header.Get("Proxy-Authorization"))
		if r.Method != http.MethodConnect {
			p.forwarded = append(p.forwarded, r.URL.String())
			p.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		p.connects = append(p.connects, r.Host)
		p.mu.Unlock()
		// The origin is named example.com, which httptest's certificate holds, so that it is not loopback and goes
		// through the proxy; the proxy reaches it on this host.
		_, port, _ := net.SplitHostPort(r.Host)
		dial := net.JoinHostPort("127.0.0.1", port)
		if p.intercept != "" {
			dial = p.intercept
		}
		upstream, err := net.DialTimeout("tcp", dial, 5*time.Second) //nolint:gosec // G704: a test proxy dialling the test's own loopback servers
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hijacker, _ := w.(http.Hijacker)
		conn, _, err := hijacker.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close() }()
		go func() { _, _ = io.Copy(conn, upstream); _ = conn.Close() }()
	}))
	t.Cleanup(p.Close)
	return p
}

func proxyURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// clientVia is the egress client through proxy, trusting target's test certificate as the system roots would trust a
// public server's.
func clientVia(t *testing.T, proxy *Proxy, target *httptest.Server) *http.Client {
	t.Helper()
	client, err := NewClient(5*time.Second, Options{Proxy: proxy})
	if err != nil {
		t.Skipf("no system roots: %v", err)
	}
	transport := client.Transport.(*http.Transport).Clone()
	if target != nil {
		transport.TLSClientConfig = target.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	}
	return &http.Client{Transport: transport, Timeout: client.Timeout}
}

// servers.md rule 30: https goes through the forward proxy by CONNECT only, with the credentials from the file as
// Basic Proxy-Authorization; TLS ends at the origin, so the proxy learns the host and port and nothing else.
func TestServerRule30_HTTPSGoesThroughTheProxyByCONNECTOnly(t *testing.T) {
	var reached string
	target := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { reached = r.URL.Path }))
	t.Cleanup(target.Close)
	fp := newForwardProxy(t)
	proxy := &Proxy{HTTPS: proxyURL(t, fp.URL), Credentials: url.UserPassword("svc", "s3cret")}
	origin := strings.Replace(target.URL, "127.0.0.1", "example.com", 1)
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, origin+"/secret-path", http.NoBody)
	response, err := clientVia(t, proxy, target).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if reached != "/secret-path" {
		t.Errorf("the origin got %q", reached)
	}
	fp.mu.Lock()
	defer fp.mu.Unlock()
	if len(fp.connects) != 1 || fp.connects[0] != strings.TrimPrefix(origin, "https://") || len(fp.forwarded) != 0 {
		t.Errorf("connects %v, forwarded %v", fp.connects, fp.forwarded)
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc:s3cret")); fp.auth[0] != want {
		t.Errorf("Proxy-Authorization = %q", fp.auth[0])
	}
}

// servers.md rule 30: plain http for self-verifying data is forwarded through the http proxy; plain http for anything
// else is refused before the proxy sees it.
func TestServerRule30_PlainHTTPGoesThroughTheProxyOnlyForSelfVerifyingData(t *testing.T) {
	fp := newForwardProxy(t)
	client := clientVia(t, &Proxy{HTTP: proxyURL(t, fp.URL)}, nil)
	refused, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://ocsp.example/", http.NoBody)
	if _, err := client.Do(refused); !errors.Is(err, ErrPlainHTTP) {
		t.Fatalf("err = %v, want ErrPlainHTTP", err)
	}
	marked, _ := http.NewRequestWithContext(SelfVerifying(t.Context()), http.MethodGet, "http://ocsp.example/status", http.NoBody)
	response, err := client.Do(marked)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	fp.mu.Lock()
	defer fp.mu.Unlock()
	if len(fp.forwarded) != 1 || fp.forwarded[0] != "http://ocsp.example/status" {
		t.Errorf("forwarded %v", fp.forwarded)
	}
}

// servers.md rule 30: a proxy URL with user information is refused, its value never quoted; credentials come from a
// file.
func TestServerRule30_AProxyURLWithUserInformationIsRefused(t *testing.T) {
	withUser := (&url.URL{Scheme: "http", User: url.UserPassword("svc", "s3cret"), Host: "proxy.example:3128"}).String()
	for name, env := range map[string]map[string]string{
		"HTTPS_PROXY":     {"HTTPS_PROXY": withUser},
		"http_proxy":      {"http_proxy": withUser},
		"another scheme":  {"HTTPS_PROXY": "socks5://proxy.example:1080"},
		"a path":          {"HTTPS_PROXY": "http://proxy.example:3128/path"},
		"not even a host": {"HTTPS_PROXY": "http://"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ProxyFromEnv(func(k string) string { return env[k] })
			if !errors.Is(err, ErrProxy) || strings.Contains(err.Error(), "s3cret") {
				t.Errorf("err = %v", err)
			}
		})
	}
	proxy, err := ProxyFromEnv(func(k string) string {
		return map[string]string{"https_proxy": "proxy.example:3128", "NO_PROXY": "internal.example"}[k]
	})
	if err != nil || proxy.HTTPS.String() != "http://proxy.example:3128" || proxy.HTTP != nil || proxy.NoProxy != "internal.example" {
		t.Errorf("proxy = %v, %v", proxy, err)
	}
	if none, err := ProxyFromEnv(func(string) string { return "" }); none != nil || err != nil {
		t.Errorf("unset: %v, %v", none, err)
	}
}

// servers.md rule 30: hosts on NO_PROXY, loopback and localhost are reached direct; every other one through the
// proxy.
func TestServerRule30_NoProxyHostsAreReachedDirect(t *testing.T) {
	proxy := &Proxy{HTTPS: proxyURL(t, "http://proxy.example:3128"), NoProxy: "internal.example, .corp.example, 10.0.0.0/8, 192.0.2.7, api.example:8443"}
	for target, wantDirect := range map[string]bool{
		"https://internal.example/":      true,
		"https://a.internal.example/":    true,
		"https://corp.example/":          true,
		"https://x.corp.example/":        true,
		"https://10.1.2.3/":              true,
		"https://192.0.2.7/":             true,
		"https://api.example:8443/":      true,
		"https://api.example/":           false,
		"https://notinternal.example/":   false,
		"https://idp.example/":           false,
		"https://127.0.0.1/":             true,
		"https://[::1]/":                 true,
		"https://localhost/":             true,
		"https://internal.example.evil/": false,
	} {
		chosen, err := proxy.choose(httptest.NewRequest(http.MethodGet, target, nil))
		if err != nil || (chosen == nil) != wantDirect {
			t.Errorf("%s: proxy %v, %v; want direct %v", target, chosen, err, wantDirect)
		}
	}
	all := &Proxy{HTTPS: proxyURL(t, "http://proxy.example:3128"), NoProxy: "*"}
	if chosen, _ := all.choose(httptest.NewRequest(http.MethodGet, "https://idp.example/", nil)); chosen != nil {
		t.Error("NO_PROXY=* still proxied")
	}
}

// servers.md rules 7 and 14: the proxy in effect is reported without its credentials, and a credentials file is one
// line of user:password.
func TestServerRule30_TheProxyIsReportedWithoutItsCredentials(t *testing.T) {
	credentials, err := ParseProxyCredentials([]byte("svc:s3cret\n"))
	if err != nil {
		t.Fatal(err)
	}
	proxy := &Proxy{HTTPS: proxyURL(t, "http://proxy.example:3128"), Credentials: credentials}
	if s := proxy.String(); strings.Contains(s, "s3cret") || strings.Contains(s, "svc") || !strings.Contains(s, "proxy.example:3128") {
		t.Errorf("String() = %q", s)
	}
	for _, bad := range []string{"", "no-colon", ":password-only", "svc:pw\nsecond:line"} {
		if _, err := ParseProxyCredentials([]byte(bad)); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
}

// servers.md rule 30: a TLS-intercepting proxy is not supported: no CA of the proxy is accepted, so a proxy that
// answers the CONNECT with a TLS server of its own fails the handshake.
func TestServerRule30_ATLSInterceptingProxyFailsTheHandshake(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(target.Close)
	// httptest's TLS servers all share one built-in certificate, so the interceptor gets one of its own, for the
	// same name, as an intercepting proxy mints.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	interceptor := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	interceptor.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	interceptor.StartTLS()
	t.Cleanup(interceptor.Close)
	fp := newForwardProxy(t)
	fp.intercept = strings.TrimPrefix(interceptor.URL, "https://")
	origin := strings.Replace(target.URL, "127.0.0.1", "example.com", 1)
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, origin+"/", http.NoBody)
	if _, err := clientVia(t, &Proxy{HTTPS: proxyURL(t, fp.URL)}, target).Do(request); err == nil {
		t.Fatal("the intercepting proxy's certificate was taken")
	}
}

// servers.md rule 30 and naming-and-config.md: the credentials come from the file the host's *_PATH variable names;
// credentials without a proxy are refused.
func TestServerRule30_ProxyCredentialsComeFromAFile(t *testing.T) {
	files := map[string][]byte{"/run/secrets/proxy": []byte("svc:s3cret\n")}
	read := func(path string) ([]byte, error) {
		if b, ok := files[path]; ok {
			return b, nil
		}
		return nil, errors.New("no such file")
	}
	env := map[string]string{"HTTPS_PROXY": "http://proxy.example:3128", "PEP_EGRESS_PROXY_CREDENTIALS_PATH": "/run/secrets/proxy"}
	proxy, err := ProxyFromHost(func(k string) string { return env[k] }, read, "PEP_EGRESS_PROXY_CREDENTIALS_PATH")
	if err != nil || proxy.Credentials.Username() != "svc" {
		t.Fatalf("proxy = %v, %v", proxy, err)
	}
	delete(env, "HTTPS_PROXY")
	if _, err := ProxyFromHost(func(k string) string { return env[k] }, read, "PEP_EGRESS_PROXY_CREDENTIALS_PATH"); !errors.Is(err, ErrProxy) {
		t.Errorf("credentials without a proxy: %v", err)
	}
}
