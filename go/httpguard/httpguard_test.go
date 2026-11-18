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

package httpguard_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/httpguard"
)

// hostilePaths are the rule's hostile inputs for a path, each refused.
var hostilePaths = []string{
	"", "pub", "/pub/%2e%2e/private/x", "/public/..%2Fprivate/x", "/pub/%2E%2e/x", "/pub/../x", "/pub/./x",
	"/pub/..", "/pub/.", "/a%2fb", "/a%2Fb", "/a%5cb", "/a%5Cb", "/a\\b", "/a%00b", "/a%252e%252e/x",
	"/a%25", "/a%", "/a%2", "/a%zz", "/a%0d%0aSet-Cookie:x", "/a\r\nb", "/a b", "/a\x00b", "/a\x7fb",
	"/ä", "/a%61", "/a%7e", "//evil.example/x", "/a//b", "/%2e", "/..%2f", "/.?", "/a?b", "/a#b",
}

// Server rule 28, "Method and path": encoded separators, NUL, dot segments (literal or encoded) and double
// encoding are refused, never cleaned up into a match.
func TestServerRule28_ANonCanonicalPathIsRefused(t *testing.T) {
	for _, path := range hostilePaths {
		if err := httpguard.CheckPath(path); !errors.Is(err, httpguard.ErrPath) {
			t.Errorf("CheckPath(%q) = %v", path, err)
		}
	}
}

func TestServerRule28_ACanonicalPathPasses(t *testing.T) {
	for _, path := range []string{"/", "/pub", "/pub/", "/pub/x.json", "/a%20b", "/a%2Bb", "/a%3Fb", "/v1/..x/y", "/.well-known/openid-federation", "/a/b/"} {
		if err := httpguard.CheckPath(path); err != nil {
			t.Errorf("CheckPath(%q) = %v", path, err)
		}
	}
}

// The path is checked as received: net/http decodes %2e%2e into URL.Path, the check sees the encoding.
func TestServerRule28_APathIsCheckedAsReceived(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/pub/%2e%2e/private", nil)
	if err := httpguard.Path(r); !errors.Is(err, httpguard.ErrPath) {
		t.Errorf("Path = %v (URL.Path %q)", err, r.URL.Path)
	}
}

// Server rule 28, "Method and path": a route prefix matches on a segment boundary only.
func TestServerRule28_APrefixMatchesOnASegmentBoundary(t *testing.T) {
	for _, c := range []struct {
		path, prefix string
		want         bool
	}{
		{"/pub", "/pub", true},
		{"/pub/x", "/pub", true},
		{"/public", "/pub", false},
		{"/public/x", "/pub", false},
		{"/pub/x", "/pub/", true},
		{"/pub", "/pub/", false},
		{"/x", "/", true},
		{"/pu", "/pub", false},
	} {
		if got := httpguard.HasPrefix(c.path, c.prefix); got != c.want {
			t.Errorf("HasPrefix(%q, %q) = %v", c.path, c.prefix, got)
		}
	}
}

// RFC 6749 section 3.1 and server rule 28, "Parameters": a repeated parameter is refused, naming the key.
func TestRFC6749_3_1_ARepeatedParameterIsRefused(t *testing.T) {
	values, err := url.ParseQuery("state=a&state=b&code=c")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := httpguard.Value(values, "state"); !errors.Is(err, httpguard.ErrRepeated) || !strings.Contains(err.Error(), "state") {
		t.Errorf("Value(state) = %v", err)
	}
	if v, err := httpguard.Value(values, "code"); v != "c" || err != nil {
		t.Errorf("Value(code) = %q, %v", v, err)
	}
	if v, err := httpguard.Value(values, "absent"); v != "" || err != nil {
		t.Errorf("Value(absent) = %q, %v", v, err)
	}
	if err := httpguard.Single(values); !errors.Is(err, httpguard.ErrRepeated) {
		t.Errorf("Single = %v", err)
	}
	if err := httpguard.Single(url.Values{"a": {"1"}, "b": {"2"}}); err != nil {
		t.Errorf("Single = %v", err)
	}
}

// Server rule 28, "Headers": Host is one of the configured names, compared as received.
func TestServerRule28_AHostOutsideTheConfiguredNamesIsRefused(t *testing.T) {
	names := []string{"pep.example", "pep.example:8443"}
	for host, want := range map[string]bool{
		"pep.example": true, "pep.example:8443": true, "PEP.example": false, "pep.example.": false,
		"pep.example:443": false, "evil.example": false, "": false,
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		if err := httpguard.Host(r, names); (err == nil) != want || (err != nil && !errors.Is(err, httpguard.ErrHost)) {
			t.Errorf("Host(%q) = %v", host, err)
		}
	}
}
