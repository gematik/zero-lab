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

package epa

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gematik/zero-lab/go/epa/vau"
	"github.com/gematik/zero-lab/go/httpguard"
)

// rule28Proxy is a proxy with its routes whose sessions come from login; a test that must not reach a session
// passes a login that fails it.
func rule28Proxy(t *testing.T, maxRequestBytes int64, login func(ProviderNumber) (*Session, error)) *Proxy {
	t.Helper()
	p := &Proxy{
		mux:             http.NewServeMux(),
		records:         map[string]PatientRecordMetadata{},
		maxRequestBytes: maxRequestBytes,
		sessionManager:  &sessionManager{sessions: map[ProviderNumber]*Session{}, login: login},
	}
	p.registerRoutes()
	return p
}

func noSession(t *testing.T) func(ProviderNumber) (*Session, error) {
	return func(ProviderNumber) (*Session, error) {
		t.Error("a session was opened for a request that should have been refused first")
		return nil, errors.New("no session")
	}
}

func serve(p *Proxy, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

var provider1 = strconv.Itoa(int(AllProviders[0]))

// Server rule 28, "Method and path": each route takes its declared methods only, and another gets 405 with Allow.
func TestServerRule28_EachRouteTakesItsDeclaredMethodsOnly(t *testing.T) {
	p := rule28Proxy(t, DefaultMaxRequestBytes, noSession(t))
	for _, c := range []struct{ method, target string }{
		{http.MethodPatch, "/providers/" + provider1 + "/vau/epa/x"},
		{http.MethodPatch, "/insurants/X000000001/vau/epa/x"},
		{http.MethodPost, "/providers"},
		{http.MethodDelete, "/info"},
		{"TRACE", "/providers/" + provider1 + "/information/api/v1/ehr"},
	} {
		rec := serve(p, c.method, c.target)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") == "" {
			t.Errorf("%s %s: %d, Allow %q", c.method, c.target, rec.Code, rec.Header().Get("Allow"))
		}
	}
	dst := http.Header{}
	copyAndPrepareHeaders(http.Header{"X-Http-Method-Override": {"DELETE"}, "X-Method-Override": {"DELETE"}, "X-Http-Method": {"DELETE"}}, dst)
	for _, name := range []string{"X-Http-Method-Override", "X-Method-Override", "X-Http-Method"} {
		if dst.Get(name) != "" {
			t.Errorf("%s is forwarded", name)
		}
	}
}

// Server rule 28, "Method and path", "Parameters" and "Values": a forwarded path with an encoded separator, a dot
// segment or double encoding, a repeated or malformed query parameter and an insurant ID outside the KVNR grammar
// get 400 before any session is opened.
func TestServerRule28_AForwardedTargetOutsideItsGrammarIsRefused(t *testing.T) {
	p := rule28Proxy(t, DefaultMaxRequestBytes, noSession(t))
	vauPath := "/providers/" + provider1 + "/vau"
	for _, target := range []string{
		vauPath + "/epa/a%2Fb",
		vauPath + "/epa/%2e%2e/x",
		vauPath + "/epa/../x",
		vauPath + "/epa/a%252e",
		vauPath + "/epa/a%00",
		vauPath + "/epa/a%5Cb",
		vauPath + "/epa//x",
		vauPath + "/epa/x?a=1&a=2",
		vauPath + "/epa/x?a=%zz",
		vauPath + "/epa/x?a=1;b=2",
		"/providers/" + provider1 + "/information/%2e%2e/x",
		"/insurants/X000000001/vau/epa/%2e%2e/x",
		"/insurants/x000000001/vau/epa/x",
		"/insurants/X00000000/vau/epa/x",
		"/insurants/X0000000011/vau/epa/x",
	} {
		if rec := serve(p, http.MethodGet, target); rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s: %d %s", target, rec.Code, rec.Body)
		}
	}
}

// vauFront is a proxy over one VAU session at a test Aktensystem, which reports each inner request it gets.
func vauFront(t *testing.T) (*Proxy, <-chan *http.Request) {
	t.Helper()
	inner := make(chan *http.Request, 1)
	vauServer, err := vau.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	vauServer.Inner = func(raw []byte) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			t.Error(err)
			return
		}
		inner <- req
	}
	aktensystem := httptest.NewServer(vauServer)
	t.Cleanup(aktensystem.Close)
	channel, err := vau.OpenChannel(aktensystem.URL, vau.EnvNonPU, aktensystem.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := &Session{VAUChannel: channel}
	return rule28Proxy(t, DefaultMaxRequestBytes, func(ProviderNumber) (*Session, error) { return session, nil }), inner
}

// Server rule 28, "Reject, never repair": an encoded '?' or '#' stays in the inner request's path, and the query
// the Aktensystem gets is the one the proxy checked.
func TestServerRule28_AnEncodedReservedCharacterStaysInTheInnerPath(t *testing.T) {
	p, inner := vauFront(t)
	rec := serve(p, http.MethodGet, "/providers/"+provider1+"/vau/epa/x%3Fy%23z?b=2&a=%C3%A4")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	got := <-inner
	if got.RequestURI != "/epa/x%3Fy%23z?a=%C3%A4&b=2" {
		t.Errorf("inner request URI = %q", got.RequestURI)
	}
}

// Server rule 28, "Output": of the Aktensystem's response headers only an allowlist reaches the client.
func TestServerRule28_OnlyAllowlistedResponseHeadersAreRelayed(t *testing.T) {
	aktensystem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for name, v := range map[string]string{
			"Content-Type": "application/json", "Etag": `"1"`, "X-Request-Id": "r",
			"Set-Cookie": "sid=1", "Server": "aktensystem/1.2", "X-Powered-By": "x",
			"Strict-Transport-Security": "max-age=1", "Location": "https://elsewhere.example/",
			"Access-Control-Allow-Origin": "*",
		} {
			w.Header().Set(name, v)
		}
		_, _ = w.Write([]byte("{}"))
	}))
	defer aktensystem.Close()
	p := rule28Proxy(t, DefaultMaxRequestBytes, func(provider ProviderNumber) (*Session, error) {
		return &Session{Client: &Client{ProviderNumber: provider, BaseURL: aktensystem.URL, HTTPClient: aktensystem.Client()}}, nil
	})
	rec := serve(p, http.MethodGet, "/providers/"+provider1+"/information/api/v1/ehr")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	for name := range rec.Header() {
		if !slices.Contains(relayedHeaderNames, name) {
			t.Errorf("%s relayed", name)
		}
	}
	for _, name := range []string{"Content-Type", "Etag", "X-Request-Id"} {
		if rec.Header().Get(name) == "" {
			t.Errorf("%s not relayed", name)
		}
	}
}

// Server rule 28, "Limits before work": a body above the limit gets 413 before any session is opened, whether
// its length is declared or not.
func TestServerRule28_AnOversizedBodyIsRefusedBeforeWork(t *testing.T) {
	p := rule28Proxy(t, 16, noSession(t))
	for _, target := range []string{
		"/providers/" + provider1 + "/vau/epa/x",
		"/providers/" + provider1 + "/information/x",
		"/insurants/X000000001/vau/epa/x",
	} {
		for _, declared := range []bool{true, false} {
			req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(strings.Repeat("x", 17)))
			if !declared {
				req.ContentLength = -1
			}
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("POST %s, length declared %v: %d", target, declared, rec.Code)
			}
		}
	}
}

// Server rule 28, "Outbound responses": the Aktensystem client refuses a redirect, and the request goes nowhere
// else.
func TestServerRule28_ARedirectingAktensystemIsRefused(t *testing.T) {
	var followed atomic.Bool
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	defer elsewhere.Close()
	aktensystem := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/information/api/v1/ehr", http.StatusFound)
	}))
	defer aktensystem.Close()
	roots := aktensystem.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	client, err := NewClient(EnvDev, AllProviders[0], nil, WithTLSConfig(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	client.BaseURL = aktensystem.URL
	if _, err := client.GetRecordStatus("X000000001"); !errors.Is(err, ErrRedirect) {
		t.Errorf("GetRecordStatus = %v", err)
	}
	if followed.Load() {
		t.Error("the redirect was followed")
	}
}

// fuzzBases are provider base URLs with and without a path of their own.
var fuzzBases = []string{"https://epa-as-1.dev.epa4all.de", "https://aktensystem.example:8443/base/v1"}

// assertBelowProvider fails unless target is an https URL on base's host, without user, query or fragment, whose
// path is canonical and lies under base's path.
func assertBelowProvider(t *testing.T, base, target, from string) {
	t.Helper()
	b, _ := url.Parse(base)
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("%q gave a target that does not parse: %q", from, target)
	}
	if u.Scheme != b.Scheme || u.Host != b.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		httpguard.CheckPath(u.EscapedPath()) != nil || (b.Path != "" && !httpguard.HasPrefix(u.EscapedPath(), b.EscapedPath())) {
		t.Fatalf("%q left the provider %q: %q", from, base, target)
	}
}

// FuzzProviderURL asserts that whatever path a request picks, an accepted target stays on the provider and under
// its path, and a refusal is never repaired into one.
func FuzzProviderURL(f *testing.F) {
	for _, seed := range []string{"/information/api/v1/ehr", "/..", "/a/%2e%2e/b", "/%2F%2Fevil.example", "//evil.example", "/a%3Fb", "/@evil", "/"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, path string) {
		for _, base := range fuzzBases {
			target, err := providerURL(base, path)
			if err != nil {
				continue
			}
			assertBelowProvider(t, base, target, path)
		}
	})
}

// FuzzForwardedTarget asserts what the proxy passes on of a request's target: a canonical path that parses back
// to no query or fragment, a query that parses strictly to what was sent, and, joined to a provider's base URL, a
// target below it.
func FuzzForwardedTarget(f *testing.F) {
	for _, seed := range [][2]string{
		{"/epa/x", "a=1"},
		{"/epa/x%3Fy%23z", "b=2&a=1"},
		{"/epa/%2e%2e/x", ""},
		{"/epa/x", "a=1&a=2"},
		{"/epa/a%2Fb", ""},
		{"/epa/x", "a=%00"},
		{"", ""},
		{"/", "a"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, path, query string) {
		const prefix = "/providers/1/vau"
		u, err := url.Parse("https://proxy.example" + prefix + path)
		if err != nil || u.RawQuery != "" || u.Fragment != "" {
			return
		}
		u.RawQuery = query
		r := &http.Request{Method: http.MethodGet, URL: u}
		gotPath, gotQuery, ok := forwardedTarget(httptest.NewRecorder(), r, prefix)
		if !ok {
			return
		}
		if httpguard.CheckPath(gotPath) != nil {
			t.Fatalf("forwarded a non-canonical path %q", gotPath)
		}
		if inner, err := url.Parse(gotPath); err != nil || inner.RawQuery != "" || inner.Fragment != "" {
			t.Fatalf("path %q splits into a query or fragment", gotPath)
		}
		sent, err := httpguard.Query(query)
		if err != nil {
			t.Fatalf("forwarded a query that does not parse strictly: %q", query)
		}
		got, err := httpguard.Query(gotQuery)
		if err != nil || len(got) != len(sent) {
			t.Fatalf("query %q forwarded as %q", query, gotQuery)
		}
		for key, v := range sent {
			if got.Get(key) != v[0] {
				t.Fatalf("query %q forwarded as %q", query, gotQuery)
			}
		}
		for _, base := range fuzzBases {
			target, err := providerURL(base, gotPath)
			if err != nil {
				t.Fatalf("a forwarded path %q has no target at %q: %v", gotPath, base, err)
			}
			assertBelowProvider(t, base, target, gotPath)
		}
	})
}
