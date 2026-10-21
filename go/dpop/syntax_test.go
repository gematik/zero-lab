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

package dpop

import "testing"

// RFC 3986 Section 5.2.4 states two worked examples of remove_dot_segments.
func TestRFC3986_5_2_4_RemoveDotSegmentsWorkedExamples(t *testing.T) {
	for in, want := range map[string]string{
		"/a/b/c/./../../g":   "/a/g",
		"mid/content=5/../6": "mid/6",
	} {
		if got := removeDotSegments(in); got != want {
			t.Errorf("removeDotSegments(%q) = %q, want %q", in, got, want)
		}
	}
}

// RFC 3986 Section 5.4 resolves references against the base http://a/b/c/d;p?q. For the
// path-only references, the merged path of Section 5.2.3 is "/b/c/" + reference (or the
// reference itself when it starts with "/"); remove_dot_segments of it must be the path of the
// result Section 5.4 states.
func TestRFC3986_5_4_RemoveDotSegmentsOfTheReferenceExamples(t *testing.T) {
	for ref, want := range map[string]string{
		"g": "/b/c/g", "./g": "/b/c/g", "g/": "/b/c/g/", ";x": "/b/c/;x", "g;x": "/b/c/g;x",
		".": "/b/c/", "./": "/b/c/", "..": "/b/", "../": "/b/", "../g": "/b/g",
		"../..": "/", "../../": "/", "../../g": "/g",
		// Section 5.4.2, abnormal examples.
		"../../../g": "/g", "../../../../g": "/g", "/./g": "/g", "/../g": "/g",
		"g.": "/b/c/g.", ".g": "/b/c/.g", "g..": "/b/c/g..", "..g": "/b/c/..g",
		"./../g": "/b/g", "./g/.": "/b/c/g/", "g/./h": "/b/c/g/h", "g/../h": "/b/c/h",
		"g;x=1/./y": "/b/c/g;x=1/y", "g;x=1/../y": "/b/c/y",
	} {
		merged := "/b/c/" + ref
		if ref[0] == '/' {
			merged = ref
		}
		if got := removeDotSegments(merged); got != want {
			t.Errorf("reference %q: removeDotSegments(%q) = %q, want %q", ref, merged, got, want)
		}
	}
}

// RFC 3986 Sections 6.2.2 and 6.2.3, as Section 4.3 of RFC 9449 recommends them for htu.
func TestRFC3986_6_2_HtuNormalization(t *testing.T) {
	//nolint:gosec // G101: URLs of a token endpoint, no credentials.
	for in, want := range map[string]string{
		"https://as.example.test/token":          "https://as.example.test/token",
		"HTTPS://AS.EXAMPLE.TEST/token":          "https://as.example.test/token",      // 6.2.2.1
		"https://as.example.test/%7etoken%2f%41": "https://as.example.test/~token%2FA", // 6.2.2.1, 6.2.2.2
		"https://as.example.test/a/./b/../c":     "https://as.example.test/a/c",        // 6.2.2.3
		"http://as.example.test:80/":             "http://as.example.test/",            // 6.2.3
		"https://as.example.test:443/x":          "https://as.example.test/x",          // 6.2.3
		"http://as.example.test:443/x":           "http://as.example.test:443/x",       // not http's default
		"https://as.example.test":                "https://as.example.test/",           // 6.2.3, empty path
		"https://as.example.test/x?q=1#f":        "https://as.example.test/x",          // RFC 9449 4.2
		"https://[2001:DB8::1]:443/x":            "https://[2001:db8::1]/x",
		"https://as.example.test/%E2%82%AC":      "https://as.example.test/%E2%82%AC",
	} {
		got, err := normalizeHTU(in)
		if err != nil || got != want {
			t.Errorf("normalizeHTU(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "/token", "ftp://as.example.test/", "https:opaque", "https://u:p@as.example.test/", "https://as.example.test/%zz", "https:///token", "http://:"} {
		if got, err := normalizeHTU(in); err == nil {
			t.Errorf("normalizeHTU(%q) = %q, want an error", in, got)
		}
	}
}

// Normalization is idempotent: a normalized URI normalizes to itself.
func TestRFC3986_6_2_HtuNormalizationIsIdempotent(t *testing.T) {
	for _, in := range []string{"HTTPS://A.test:443/./b/../%7e%41?q#f", "http://a.test:8080/x/%2f"} {
		once, err := normalizeHTU(in)
		if err != nil {
			t.Fatal(err)
		}
		if twice, err := normalizeHTU(once); err != nil || twice != once {
			t.Errorf("%q: %q then %q, %v", in, once, twice, err)
		}
	}
}

// token68 (RFC 9110 Section 11.2), the syntax of the DPoP header (Section 4.1, Figure 3) and
// of DPoP credentials (Section 7.1, Figure 12).
func TestRFC9110_11_2_Token68(t *testing.T) {
	for _, s := range []string{"a", "aZ09-._~+/", "abc=", "abc==", "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"} {
		if !isToken68(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", "=", "a b", "a,b", "a=b", "a\"", "ä"} {
		if isToken68(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

// The nonce syntax of Section 8.1: 1*NQCHAR, NQCHAR = %x21 / %x23-5B / %x5D-7E.
func TestRFC9449_8_1_NonceSyntax(t *testing.T) {
	for _, s := range []string{"!", "eyJ7S_zG.eyJH0-Z.HX4w-7v", "#[]~"} {
		if !isNonce(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", " ", "a\"b", "a\\b", "a\x7f"} {
		if isNonce(s) {
			t.Errorf("%q accepted", s)
		}
	}
}
