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

package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/httpguard"
)

// forwarded records the URL a gateway sends upstream and answers 200, so no upstream runs.
type forwarded struct{ urls []*url.URL }

func (f *forwarded) RoundTrip(r *http.Request) (*http.Response, error) {
	f.urls = append(f.urls, r.URL)
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
}

// rule28Gateway has an open route that strips its prefix and a gated one, both to upstreams with a path.
func rule28Gateway(t testing.TB, upstream *forwarded) *Gateway {
	t.Helper()
	gw, err := newGateway([]Route{
		{PathPrefix: "/pub", Upstream: "http://open.internal/base", Gate: GateNone, StripPrefix: true},
		{PathPrefix: "/private", Upstream: "http://gated.internal/base", Gate: GateSession},
	}, gatewayDeps{log: slog.New(slog.DiscardHandler), currentSession: staticSession(nil), backend: &fakeBackend{}, transport: upstream})
	if err != nil {
		t.Fatal(err)
	}
	return gw
}

// Server rule 28, "Method and path": an encoded dot segment or separator gets 400 before routing, so it never
// reaches an upstream that would resolve it into a gated route; a prefix matches on a segment boundary only.
func TestServerRule28_TheGatewayMatchesTheCanonicalPathOnly(t *testing.T) {
	upstream := &forwarded{}
	gw := rule28Gateway(t, upstream)
	for _, path := range []string{"/pub/%2e%2e/private/x", "/public/..%2Fprivate/x", "/pub/%2E%2E/private", "/pub/a%5c..%5cprivate", "/pub/%252e%252e/private", "/pub/x%00"} {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/public/x", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("/public/x matched /pub: %d", rec.Code)
	}
	if len(upstream.urls) != 0 {
		t.Errorf("forwarded %v", upstream.urls)
	}

	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pub/a%20b/c", nil))
	if rec.Code != http.StatusOK || len(upstream.urls) != 1 || upstream.urls[0].EscapedPath() != "/base/a%20b/c" {
		t.Errorf("forwarded %d %v", rec.Code, upstream.urls)
	}
}

func TestServerRule28_ARoutePrefixIsACanonicalPath(t *testing.T) {
	for _, prefix := range []string{"/pub/../x", "/a%2fb", "pub", "//pub"} {
		if _, err := validateRoutes([]Route{{PathPrefix: prefix, Upstream: "http://u"}}); err == nil {
			t.Errorf("prefix %q accepted", prefix)
		}
	}
}

// FuzzGatewayRoute asserts what reaches an upstream: a path under that upstream's own path, canonical, with no
// dot segment, and only through the route whose prefix holds the request's path on a segment boundary.
func FuzzGatewayRoute(f *testing.F) {
	for _, path := range []string{
		"/pub/x", "/pub", "/pub/", "/public/x", "/private/x", "/pub/%2e%2e/private/x", "/public/..%2Fprivate/x",
		"/pub/..", "/pub//private", "/pub/%252e", "/pub/a%5cb", "/pub/a%00", "/pub/%c0%ae%c0%ae/x", "/pub/a?b=../c",
	} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		u, err := url.ParseRequestURI(path)
		if err != nil || u.Scheme != "" || u.Host != "" {
			return
		}
		r := &http.Request{Method: http.MethodGet, URL: u, RequestURI: path, Header: http.Header{}, Host: "pep.example", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
		upstream := &forwarded{}
		gw := rule28Gateway(t, upstream)
		gw.ServeHTTP(httptest.NewRecorder(), r)
		if len(upstream.urls) == 0 {
			return
		}
		got := upstream.urls[0]
		if got.Host != "open.internal" {
			t.Fatalf("%q reached %s", path, got.Host)
		}
		if !httpguard.HasPrefix(u.EscapedPath(), "/pub") {
			t.Fatalf("%q went through /pub", path)
		}
		if !strings.HasPrefix(got.EscapedPath(), "/base/") && got.EscapedPath() != "/base" {
			t.Fatalf("%q forwarded as %q", path, got.EscapedPath())
		}
		if err := httpguard.CheckPath(got.EscapedPath()); err != nil {
			t.Fatalf("%q forwarded as non-canonical %q", path, got.EscapedPath())
		}
	})
}
