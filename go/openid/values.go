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

package openid

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Bounds of the request values a login may carry. They travel in a URL or a PAR form, where providers cap the size,
// and nothing a login needs comes near them.
const (
	// MaxClaimsBytes bounds the claims request parameter.
	MaxClaimsBytes = 4096
	// maxClaimsDepth bounds the nesting of objects and arrays in the claims parameter; OIDC Core 5.5 needs three.
	maxClaimsDepth = 5
	// maxClaimsMembers bounds the members of all objects of the claims parameter together.
	maxClaimsMembers = 64
	// maxScopes and maxACRValues bound how many values a request names.
	maxScopes    = 16
	maxACRValues = 8
	// maxTokenBytes bounds one scope or acr value.
	maxTokenBytes = 128
)

// The request values AuthorizationQuery refuses. Each error names the field, never the value: what is refused may
// come from the caller's client and must not reach a log.
var (
	ErrClaimsParameter = errors.New("claims parameter refused")
	ErrScope           = errors.New("scope refused")
	ErrACRValue        = errors.New("acr value refused")
)

// checkClaimsParameter takes a JSON object (OIDC Core 5.5) of valid UTF-8, within the bounds above and without a
// member named twice in any object, since providers would resolve a duplicate each their own way. It walks the
// tokens before anything is decoded and refuses rather than repairs.
func checkClaimsParameter(claims json.RawMessage) error {
	if len(claims) > MaxClaimsBytes {
		return fmt.Errorf("%w: larger than %d bytes", ErrClaimsParameter, MaxClaimsBytes)
	}
	if !utf8.Valid(claims) {
		return fmt.Errorf("%w: not UTF-8", ErrClaimsParameter)
	}
	return walkClaims(json.NewDecoder(bytes.NewReader(claims)))
}

// claimsLevel is one open object or array of the walk.
type claimsLevel struct {
	object    bool
	names     map[string]bool
	expectKey bool
}

func walkClaims(decoder *json.Decoder) error {
	var open []*claimsLevel
	members := 0
	for started := false; ; started = true {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) && started && len(open) == 0 {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: not JSON", ErrClaimsParameter)
		}
		if !started && token != json.Delim('{') {
			return fmt.Errorf("%w: not a JSON object", ErrClaimsParameter)
		}
		if started && len(open) == 0 {
			return fmt.Errorf("%w: data after the object", ErrClaimsParameter)
		}
		if len(open) > 0 && open[len(open)-1].expectKey && token != json.Delim('}') {
			level := open[len(open)-1]
			name, _ := token.(string)
			if level.names[name] {
				return fmt.Errorf("%w: a member named twice", ErrClaimsParameter)
			}
			level.names[name] = true
			level.expectKey = false
			if members++; members > maxClaimsMembers {
				return fmt.Errorf("%w: more than %d members", ErrClaimsParameter, maxClaimsMembers)
			}
			continue
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			if len(open) == maxClaimsDepth {
				return fmt.Errorf("%w: nested deeper than %d", ErrClaimsParameter, maxClaimsDepth)
			}
			object := token == json.Delim('{')
			open = append(open, &claimsLevel{object: object, names: map[string]bool{}, expectKey: object})
			continue
		case json.Delim('}'), json.Delim(']'):
			open = open[:len(open)-1]
		}
		// A value ended: an object around it expects its next member's name.
		if len(open) > 0 && open[len(open)-1].object {
			open[len(open)-1].expectKey = true
		}
	}
}

// checkTokens holds each value to RFC 6749's scope-token = 1*NQCHAR, which space-separated acr_values share: a
// space inside one value would split it into two on the provider's side. refused is the sentinel of the field, most
// bounds how many values there may be, and unique refuses a value named twice.
func checkTokens(refused error, values []string, most int, unique bool) error {
	if len(values) > most {
		return fmt.Errorf("%w: more than %d values", refused, most)
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("%w: empty", refused)
		}
		if len(value) > maxTokenBytes {
			return fmt.Errorf("%w: longer than %d bytes", refused, maxTokenBytes)
		}
		if unique && seen[value] {
			return fmt.Errorf("%w: a value named twice", refused)
		}
		seen[value] = true
		for _, r := range value {
			if r != 0x21 && (r < 0x23 || r > 0x7e || r == 0x5c) {
				return fmt.Errorf("%w: a character outside NQCHAR", refused)
			}
		}
	}
	return nil
}
