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

// Package httpguard holds the request checks of server rule 28 that every Go server adapter calls before its
// logic sees a request, so that each check exists once and is fuzzed once: the path as received, a parameter
// that occurs once, and the Host. Each check refuses; none repairs. Errors name what was refused, never the
// value, which is the peer's (server rule 14).
package httpguard

import (
	"errors"
	"net/http"
	"strings"
)

// ErrPath refuses a path that is not canonical as received.
var ErrPath = errors.New("httpguard: the path is not canonical")

// Path checks the path of r as it was received (r.URL.EscapedPath), before any routing cleans it.
func Path(r *http.Request) error {
	return CheckPath(r.URL.EscapedPath())
}

// CheckPath checks an escaped path, as a request line or X-Forwarded-Uri carries it, without its query. It
// refuses, never cleans up into a match (server rule 28, "Method and path"):
//   - a path that does not start with "/", or holds a byte outside visible ASCII, a literal "\", or a "?" or
//     "#", which would end the path;
//   - a percent-encoding that is malformed, or encodes "/", "\", "%" (double encoding), a control character
//     or an unreserved character (RFC 3986 Section 2.3 says those are never encoded, so "%2e" is a dot in
//     disguise);
//   - a "." or ".." segment, and an empty segment ("//") anywhere but at the end.
func CheckPath(escaped string) error {
	if !strings.HasPrefix(escaped, "/") {
		return ErrPath
	}
	for i := 0; i < len(escaped); i++ {
		c := escaped[i]
		switch {
		case c == '%':
			if i+2 >= len(escaped) {
				return ErrPath
			}
			hi, ok1 := unhex(escaped[i+1])
			lo, ok2 := unhex(escaped[i+2])
			if !ok1 || !ok2 || forbiddenEncoded(hi<<4|lo) {
				return ErrPath
			}
			i += 2
		case c <= ' ' || c >= 0x7f || c == '\\' || c == '?' || c == '#':
			return ErrPath
		}
	}
	segments := strings.Split(escaped[1:], "/")
	for i, segment := range segments {
		if segment == "." || segment == ".." || (segment == "" && i < len(segments)-1) {
			return ErrPath
		}
	}
	return nil
}

// forbiddenEncoded says a byte may not appear percent-encoded in a canonical path.
func forbiddenEncoded(b byte) bool {
	switch {
	case b < 0x20 || b == 0x7f, b == '/', b == '\\', b == '%':
		return true
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9', b == '-', b == '.', b == '_', b == '~':
		return true
	}
	return false
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// HasPrefix says path lies under prefix on a segment boundary: "/pub" holds "/pub" and "/pub/x", never
// "/public". A prefix that ends in "/" holds what starts with it. Both are compared as received, so the
// path is checked (CheckPath) first.
func HasPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/'
}
