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

import (
	"errors"
	"net/url"
	"strings"
)

// defaultPorts are the ports RFC 9110 Sections 4.2.1 and 4.2.2 give http and https.
var defaultPorts = map[string]string{"http": "80", "https": "443"}

// normalizeHTU returns raw as check 9 of Section 4.3 compares it: an absolute http or https
// URI without query and fragment (Section 4.2), with RFC 3986 syntax-based (Section 6.2.2)
// and scheme-based (Section 6.2.3) normalization applied, as Section 4.3 recommends.
func normalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("not a URI")
	}
	// Case normalization of the scheme (RFC 3986 Section 6.2.2.1).
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("not an absolute http or https URI")
	}
	// An authority of only a port, as in "http://:", has no host (RFC 9110 Section 4.2.1).
	if u.Opaque != "" || u.Hostname() == "" {
		return "", errors.New("not a hierarchical URI with a host")
	}
	// RFC 9110 Section 4.2.4: a sender must not generate userinfo in an http(s) URI.
	if u.User != nil {
		return "", errors.New("userinfo in an http URI")
	}
	// Case normalization of the host (RFC 3986 Section 6.2.2.1).
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	// Scheme-based normalization: an empty or default port is omitted (Section 6.2.3).
	if port := u.Port(); port != "" && port != defaultPorts[scheme] {
		host += ":" + port
	}
	path, err := normalizePercentEncoding(u.EscapedPath())
	if err != nil {
		return "", err
	}
	// Path segment normalization (Section 6.2.2.3); an empty path is "/" (Section 6.2.3).
	path = removeDotSegments(path)
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// normalizePercentEncoding uppercases the hex digits of every percent-encoding and decodes
// those of unreserved characters (RFC 3986 Sections 6.2.2.1, 6.2.2.2).
func normalizePercentEncoding(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
			return "", errors.New("malformed percent-encoding")
		}
		c := unhex(s[i+1])<<4 | unhex(s[i+2])
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteString(strings.ToUpper(s[i+1 : i+3]))
		}
		i += 2
	}
	return b.String(), nil
}

// removeDotSegments is the algorithm of RFC 3986 Section 5.2.4, step by step.
func removeDotSegments(in string) string {
	var out []string
	for in != "" {
		switch {
		// A: a prefix of "../" or "./" is removed.
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		// B: a prefix of "/./" or "/." (complete segment) is replaced by "/".
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		// C: a prefix of "/../" or "/.." (complete segment) is replaced by "/", and the last
		// segment of the output is removed.
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			out = dropLastSegment(out)
		case in == "/..":
			in = "/"
			out = dropLastSegment(out)
		// D: an input of only "." or ".." is removed.
		case in == "." || in == "..":
			in = ""
		// E: the first segment, with its leading "/" if any, moves to the output.
		default:
			end := strings.IndexByte(in[1:], '/')
			if end < 0 {
				end = len(in)
			} else {
				end++
			}
			out = append(out, in[:end])
			in = in[end:]
		}
	}
	return strings.Join(out, "")
}

func dropLastSegment(out []string) []string {
	if len(out) == 0 {
		return out
	}
	return out[:len(out)-1]
}

// isToken68 reports whether s matches token68 (RFC 9110 Section 11.2), the syntax of the
// DPoP header value (Section 4.1, Figure 3) and of DPoP credentials (Section 7.1, Figure 12):
// 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
func isToken68(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !isAlpha(c) && !isDigit(c) && !strings.ContainsRune("-._~+/", rune(c)) {
			return false
		}
	}
	return true
}

// isToken reports whether s matches token (RFC 9110 Section 5.6.2), the syntax of an HTTP
// method (RFC 9110 Section 9.1).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(c) && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

// isNonce reports whether s matches the nonce syntax of Section 8.1: 1*NQCHAR, where
// NQCHAR is %x21 / %x23-5B / %x5D-7E (RFC 6749 Appendix A).
func isNonce(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != 0x21 && (c < 0x23 || c > 0x5b) && (c < 0x5d || c > 0x7e) {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isDigit(c byte) bool { return '0' <= c && c <= '9' }
func isHex(c byte) bool   { return isDigit(c) || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' }

// isUnreserved: ALPHA / DIGIT / "-" / "." / "_" / "~" (RFC 3986 Section 2.3).
func isUnreserved(c byte) bool {
	return isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~'
}

func unhex(c byte) byte {
	switch {
	case isDigit(c):
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
