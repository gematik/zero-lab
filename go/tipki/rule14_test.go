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

package tipki

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
)

// refusedFor says whether err refuses for reason, in its own text or in the decoder's error under it, which the text
// does not repeat (servers.md rule 14).
func refusedFor(err error, reason string) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), reason) {
		return true
	}
	var syntactic *jsontext.SyntacticError
	var semantic *json.SemanticError
	return errors.As(err, &syntactic) && strings.Contains(syntactic.Error(), reason) ||
		errors.As(err, &semantic) && strings.Contains(semantic.Error(), reason)
}

// marker and numberMarker stand for the input; an error that holds one would carry the input into a log (servers.md
// rule 14). The decoder quotes a number it cannot hold and a member's name, so those carry them.
const (
	marker       = "PEER-INPUT-7f3a"
	numberMarker = "-987654321987"
)

func requireNotQuoted(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), numberMarker) {
		t.Fatalf("the error quotes the input: %v", err)
	}
}

// Server rule 14: a bundle is refused by naming the field that is wrong, never by quoting a value or a member's name.
func TestServerRule14_ARefusedBundleIsNotQuoted(t *testing.T) {
	meta := func(source string) string { return `{"fetched_at":1,"source":"` + source + `"}` }
	head := `{"format_version":2,"label":"l","anchor_sha256":"` + strings.Repeat("0", 64) + `","roots":"","tsl":"",`
	for name, bundle := range map[string]string{
		"an unknown source":           head + `"roots_meta":` + meta(marker) + `,"tsl_meta":` + meta("http") + `}`,
		"an unknown field":            `{"` + marker + `":1}`,
		"a field twice":               `{"label":"` + marker + `","label":"` + marker + `"}`,
		"a version out of range":      `{"format_version":` + numberMarker + `,"label":"l","anchor_sha256":"","roots":"","tsl":"","roots_meta":{},"tsl_meta":{}}`,
		"a fetched_at out of range":   head + `"roots_meta":{"fetched_at":` + numberMarker + `,"source":"http"},"tsl_meta":` + meta("http") + `}`,
		"a max_age_secs out of range": head + `"roots_meta":{"fetched_at":1,"source":"http","max_age_secs":` + numberMarker + `},"tsl_meta":` + meta("http") + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseBundle([]byte(bundle))
			requireNotQuoted(t, err)
		})
	}
}

// Server rule 14: a bundle of another trust anchor is refused without its label, which is the bundle's input.
func TestServerRule14_AnotherAnchorsBundleIsNotNamed(t *testing.T) {
	err := (&Bundle{Label: marker}).CheckAnchor([]byte("anchor"))
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("got %v, want a refusal without the label", err)
	}
}

// Server rule 14: a roots.json is refused by naming the member that is wrong, never by quoting a value or a member's
// name; a member named twice still unwraps to the decoder's reason.
func TestServerRule14_ARefusedRootsDocumentIsNotQuoted(t *testing.T) {
	for name, roots := range map[string]string{
		"a member twice":         `[{"` + marker + `":1,"` + marker + `":2}]`,
		"a mistyped member":      `[{"cert":"AAAA","` + marker + `":{"a":1 x}}]`,
		"a mistyped cn":          `[{"cert":"AAAA","cn":` + numberMarker + `}]`,
		"a mistyped cert":        `[{"cert":` + numberMarker + `}]`,
		"a mistyped prev":        `[{"cert":"AAAA","prev":` + numberMarker + `}]`,
		"a wrapper member twice": `{"roots":[],"` + marker + `":1,"` + marker + `":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRoots([]byte(roots))
			requireNotQuoted(t, err)
			if name == "a member twice" && !errors.Is(err, jsontext.ErrDuplicateName) {
				t.Fatalf("got %v, want a duplicate name to unwrap", err)
			}
		})
	}
}
