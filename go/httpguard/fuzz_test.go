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
	"unicode/utf8"

	"github.com/gematik/zero-lab/go/httpguard"
)

// FuzzCheckPath asserts what an accepted path is: it starts with "/", is visible ASCII, decodes to no
// separator, NUL or further escape, and has no dot segment, decoded or not. A refusal never quotes the input.
func FuzzCheckPath(f *testing.F) {
	for _, path := range hostilePaths {
		f.Add(path)
	}
	for _, path := range []string{"/", "/pub/x", "/a%20b", "/a%C3%A4", "/\u202ex", "/a\u200bb", "/%c0%ae%c0%ae/x", "/a%E2%80%AEb"} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		err := httpguard.CheckPath(path)
		if err != nil {
			// The sentinel itself, so the refusal carries nothing of the input.
			if err != httpguard.ErrPath { //nolint:errorlint // identity, not wrapping, is the property

				t.Fatalf("refusal %v", err)
			}
			return
		}
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\ \x00") {
			t.Fatalf("accepted %q", path)
		}
		decoded, derr := url.PathUnescape(path)
		if derr != nil || strings.ContainsAny(decoded, "\\\x00%") {
			t.Fatalf("accepted %q, decoded %q", path, decoded)
		}
		for segment := range strings.SplitSeq(path, "/") {
			plain, _ := url.PathUnescape(segment)
			if plain == "." || plain == ".." || strings.Contains(plain, "/") {
				t.Fatalf("accepted %q with segment %q", path, segment)
			}
		}
		// What net/http routes on is the same path, decoded, with nothing for ServeMux to clean.
		r := httptest.NewRequest(http.MethodGet, "http://x"+path, nil)
		if err := httpguard.Path(r); err != nil {
			t.Fatalf("Path(%q) = %v, CheckPath accepted it", path, err)
		}
	})
}

// FuzzHasPrefix asserts that a match is on a segment boundary.
func FuzzHasPrefix(f *testing.F) {
	f.Add("/public/x", "/pub")
	f.Add("/pub/x", "/pub")
	f.Add("/pub", "/pub/")
	f.Fuzz(func(t *testing.T, path, prefix string) {
		if !httpguard.HasPrefix(path, prefix) {
			return
		}
		rest := path[len(prefix):]
		if rest != "" && !strings.HasSuffix(prefix, "/") && !strings.HasPrefix(rest, "/") {
			t.Fatalf("HasPrefix(%q, %q) matched inside a segment", path, prefix)
		}
	})
}

// FuzzValue asserts that a value comes back only for a key that occurs once.
func FuzzValue(f *testing.F) {
	f.Add("state=a&state=b", "state")
	f.Add("STATE=a&state=b", "state")
	f.Add("state=%00&code=c", "state")
	f.Add("a=1;a=2", "a")
	f.Fuzz(func(t *testing.T, query, key string) {
		values, err := url.ParseQuery(query)
		if err != nil {
			return
		}
		v, err := httpguard.Value(values, key)
		switch n := len(values[key]); {
		case n > 1 && !errors.Is(err, httpguard.ErrRepeated):
			t.Fatalf("Value(%q) over %q = %q, %v", key, query, v, err)
		case n <= 1 && err != nil:
			t.Fatalf("Value(%q) over %q = %v", key, query, err)
		case n == 1 && v != values[key][0]:
			t.Fatalf("Value(%q) = %q", key, v)
		}
	})
}

// FuzzQuery asserts what an accepted query is: every name non-empty and occurring once, every name and value
// text, and its encoding parsing back to the same values. A refusal is one of the sentinels.
func FuzzQuery(f *testing.F) {
	f.Add("a=1&b=2")
	f.Add("a=1&a=2")
	f.Add("a=%00")
	f.Add("a=1;b=2")
	f.Add("=x&&y")
	f.Add("a=%C3%A4+b")
	f.Fuzz(func(t *testing.T, raw string) {
		values, err := httpguard.Query(raw)
		if err != nil {
			if !errors.Is(err, httpguard.ErrQuery) && !errors.Is(err, httpguard.ErrRepeated) {
				t.Fatalf("Query(%q) = %v", raw, err)
			}
			return
		}
		for key, v := range values {
			if key == "" || len(v) != 1 || !utf8.ValidString(key) || !utf8.ValidString(v[0]) ||
				strings.ContainsFunc(key+v[0], func(r rune) bool { return r < ' ' || r == 0x7f }) {
				t.Fatalf("Query(%q) accepted %q=%q", raw, key, v)
			}
		}
		again, err := httpguard.Query(values.Encode())
		if err != nil || len(again) != len(values) {
			t.Fatalf("Query(%q): its encoding %q parses to %v, %v", raw, values.Encode(), again, err)
		}
		for key, v := range values {
			if again.Get(key) != v[0] {
				t.Fatalf("Query(%q): %q changed to %q", raw, v[0], again.Get(key))
			}
		}
	})
}

// FuzzHost asserts that only a configured name passes, byte for byte.
func FuzzHost(f *testing.F) {
	for _, host := range []string{"pep.example", "PEP.EXAMPLE", "pep.example.", "pep.example:443", "pep.example\x00", "pep.example\r\nX: y", "xn--pp-yla.example"} {
		f.Add(host)
	}
	names := []string{"pep.example", "pep.example:8443"}
	f.Fuzz(func(t *testing.T, host string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		err := httpguard.Host(r, names)
		if (err == nil) != (host == names[0] || host == names[1]) {
			t.Fatalf("Host(%q) = %v", host, err)
		}
		if err != nil && err != httpguard.ErrHost { //nolint:errorlint // identity, not wrapping: the refusal carries nothing of the input
			t.Fatalf("refusal %v", err)
		}
	})
}
