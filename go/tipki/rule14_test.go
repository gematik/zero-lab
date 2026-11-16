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
	"encoding/base64"
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

// requireRefusedFor asserts err refuses for its fixed reason and quotes none of the input.
func requireRefusedFor(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), numberMarker) {
		t.Fatalf("the error quotes the input: %v", err)
	}
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("got %v, want %q", err, reason)
	}
}

// Server rule 14: a bundle is refused by naming the field that is wrong, never by quoting a value or a member's name.
func TestServerRule14_ARefusedBundleIsNotQuoted(t *testing.T) {
	meta := func(source string) string { return `{"fetched_at":1,"source":"` + source + `"}` }
	head := `{"format_version":2,"label":"l","anchor_sha256":"` + strings.Repeat("0", 64) + `","roots":"","tsl":"",`
	for name, test := range map[string]struct{ bundle, reason string }{
		"an unknown source":           {head + `"roots_meta":` + meta(marker) + `,"tsl_meta":` + meta("http") + `}`, "roots_meta: source: not one of the known sources"},
		"an unknown field":            {`{"` + marker + `":1}`, "bundle: unknown field"},
		"a field twice":               {`{"label":"` + marker + `","label":"` + marker + `"}`, "bundle: repeated field"},
		"a version out of range":      {`{"format_version":` + numberMarker + `,"label":"l","anchor_sha256":"","roots":"","tsl":"","roots_meta":{},"tsl_meta":{}}`, "format_version: does not decode"},
		"a fetched_at out of range":   {head + `"roots_meta":{"fetched_at":` + numberMarker + `,"source":"http"},"tsl_meta":` + meta("http") + `}`, "roots_meta: fetched_at: does not decode"},
		"a max_age_secs out of range": {head + `"roots_meta":{"fetched_at":1,"source":"http","max_age_secs":` + numberMarker + `},"tsl_meta":` + meta("http") + `}`, "roots_meta: max_age_secs: does not decode"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseBundle([]byte(test.bundle))
			requireRefusedFor(t, err, test.reason)
		})
	}
}

// Server rule 14: a bundle of another trust anchor or too old is refused without its label, which is the bundle's
// input.
func TestServerRule14_ARefusedBundleIsNotNamed(t *testing.T) {
	bundle := &Bundle{Label: marker}
	requireRefusedFor(t, bundle.CheckAnchor([]byte("anchor")), "belongs to a different trust anchor")
	_, err := LoadTrustStore(bundle, AnchorProd, nil, bundle.FetchedAt.Add(MaxBundleAge), 0, nil)
	requireRefusedFor(t, err, "the bundle is")
}

// Server rule 14: a roots.json is refused by naming the member that is wrong, never by quoting a value or a member's
// name; a member named twice still unwraps to the decoder's reason.
func TestServerRule14_ARefusedRootsDocumentIsNotQuoted(t *testing.T) {
	cert := `"` + base64.StdEncoding.EncodeToString(AnchorProd) + `"`
	for name, test := range map[string]struct{ roots, reason string }{
		"a member twice":         {`[{"` + marker + `":1,"` + marker + `":2}]`, "roots.json: document: does not decode"},
		"a mistyped member":      {`[{"cert":` + cert + `,"` + marker + `":{"a":1 x}}]`, "roots.json: document: does not decode"},
		"a mistyped cn":          {`[{"cert":` + cert + `,"cn":` + numberMarker + `}]`, "entry 0: cn: does not decode"},
		"a mistyped cert":        {`[{"cert":` + numberMarker + `}]`, "entry 0: cert: does not decode"},
		"a mistyped prev":        {`[{"cert":` + cert + `,"prev":` + numberMarker + `}]`, "entry 0: prev: does not decode"},
		"a wrapper member twice": {`{"roots":[],"` + marker + `":1,"` + marker + `":2}`, "roots.json: document: does not decode"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRoots([]byte(test.roots))
			requireRefusedFor(t, err, test.reason)
			if strings.Contains(name, "twice") && !errors.Is(err, jsontext.ErrDuplicateName) {
				t.Fatalf("got %v, want a duplicate name to unwrap", err)
			}
		})
	}
}
