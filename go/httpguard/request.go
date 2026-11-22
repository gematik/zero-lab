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

package httpguard

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"unicode/utf8"
)

// ErrRepeated refuses a parameter that occurs more than once (RFC 6749 Section 3.1).
var ErrRepeated = errors.New("httpguard: a parameter occurs more than once")

// ErrHost refuses a Host that is not one of the configured names.
var ErrHost = errors.New("httpguard: the host is not a configured name")

// Value returns the one value of key: "" when it is absent, ErrRepeated, wrapped with the key, when it occurs
// more than once. Whether an empty value counts as absent is the endpoint's to say.
func Value(values url.Values, key string) (string, error) {
	switch v := values[key]; len(v) {
	case 0:
		return "", nil
	case 1:
		return v[0], nil
	}
	return "", &ParameterError{Name: key, Err: ErrRepeated}
}

// Single refuses values in which any key occurs more than once, for endpoints that read none twice.
func Single(values url.Values) error {
	for key, v := range values {
		if len(v) > 1 {
			return &ParameterError{Name: key, Err: ErrRepeated}
		}
	}
	return nil
}

// ErrQuery refuses a query that does not parse, or a name or value that is not text: an empty name, a control
// character or invalid UTF-8, after decoding.
var ErrQuery = errors.New("httpguard: the query is malformed")

// Query parses a raw query for an endpoint that reads each parameter once. A malformed escape or a ';' separator
// is ErrQuery; so is an empty name, or a name or value that decodes to a control character or invalid UTF-8.
// A repeated name is ErrRepeated. Both come wrapped in a ParameterError once a name is known.
func Query(raw string) (url.Values, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, ErrQuery
	}
	for key, v := range values {
		if key == "" || !isText(key) {
			return nil, ErrQuery
		}
		if len(v) > 1 {
			return nil, &ParameterError{Name: key, Err: ErrRepeated}
		}
		if !isText(v[0]) {
			return nil, &ParameterError{Name: key, Err: ErrQuery}
		}
	}
	return values, nil
}

// isText reports whether s is valid UTF-8 without C0 controls or DEL.
func isText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for i := range len(s) {
		if s[i] < ' ' || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// ParameterError names the parameter a check refused. The name is the endpoint's own when it asked for it
// (Value); from Single it is the peer's, so a caller that writes it into a response bounds and encodes it.
type ParameterError struct {
	Name string
	Err  error
}

func (e *ParameterError) Error() string { return e.Err.Error() + ": " + e.Name }

func (e *ParameterError) Unwrap() error { return e.Err }

// Host checks that r was sent to one of the configured names (server rule 28, "Headers"). r.Host is the Host
// header, or :authority under HTTP/2, and is compared byte for byte, port included: a name in another case
// or with a trailing dot is refused, not folded into a match.
func Host(r *http.Request, names []string) error {
	if r.Host == "" || !slices.Contains(names, r.Host) {
		return ErrHost
	}
	return nil
}
