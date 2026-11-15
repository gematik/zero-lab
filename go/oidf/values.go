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

package oidf

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// Bounds of the values the federation hands over as data.
const (
	// maxTextBytes bounds a text member: a claim of the ID token, a name on the IdP list.
	maxTextBytes = 1024
	// maxEntityIdentifierBytes bounds an entity identifier or another URL taken as data.
	maxEntityIdentifierBytes = 2048
)

// checkText takes valid UTF-8 of at most most bytes without control characters, which would let a value break a log
// line or a header it is written into. The error names the rule, never the value.
func checkText(value string, most int) error {
	if len(value) > most {
		return fmt.Errorf("longer than %d bytes", most)
	}
	if !utf8.ValidString(value) {
		return errors.New("not UTF-8")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return errors.New("holds a control character")
		}
	}
	return nil
}

// textMember reads the member name of an object as text within most bytes. A member that is absent or null is not
// present; one of another type is an error.
func textMember(members map[string]json.RawMessage, name string, most int) (value string, present bool, err error) {
	raw, ok := members[name]
	if !ok || string(raw) == "null" {
		return "", false, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false, errors.New("is no text")
	}
	if err := checkText(value, most); err != nil {
		return "", false, err
	}
	return value, true, nil
}
