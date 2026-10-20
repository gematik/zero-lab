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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type manifest struct {
	Spec  string         `json:"spec"`
	Level int            `json:"level"`
	Cases []manifestCase `json:"cases"`
}

type manifestCase struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Rules       []string `json:"rules"`
	Description string   `json:"description,omitempty"`
	Input       obj      `json:"input"`
	Expect      expect   `json:"expect"`
}

type expect struct {
	Code   string `json:"code"`
	Output obj    `json:"output,omitempty"`
}

// buildManifest evaluates every case with the reference and checks the code each case
// states, so that an expectation rests on both the hand-written rule and the reference.
func buildManifest() (manifest, error) {
	m := manifest{Spec: "spec/store", Level: 1}
	seen := map[string]bool{}
	for _, c := range allCases() {
		if seen[c.id] {
			return m, fmt.Errorf("duplicate case %s", c.id)
		}
		seen[c.id] = true
		input, err := normalize(c.input)
		if err != nil {
			return m, fmt.Errorf("%s: %w", c.id, err)
		}
		got, out, err := evaluate(c.kind, input)
		if err != nil {
			return m, fmt.Errorf("%s: %w", c.id, err)
		}
		if got != c.want {
			return m, fmt.Errorf("%s: the reference gives %s, the case states %s", c.id, got, c.want)
		}
		e := expect{Code: string(got)}
		if got == codeOK {
			if e.Output, err = normalize(out); err != nil {
				return m, fmt.Errorf("%s: %w", c.id, err)
			}
		}
		m.Cases = append(m.Cases, manifestCase{ID: c.id, Kind: c.kind, Rules: c.rules, Description: c.description, Input: input, Expect: e})
	}
	return m, nil
}

// normalize gives a value the shape it has after a round trip through JSON, with numbers
// kept exact, so that expectations and adapter answers compare with reflect.DeepEqual.
func normalize(v any) (obj, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return decodeObj(b)
}

func decodeObj(b []byte) (obj, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var o obj
	if err := d.Decode(&o); err != nil {
		return nil, err
	}
	return o, nil
}

func encodeManifest(m manifest) ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func readManifest(path string) (manifest, error) {
	var m manifest
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	err = d.Decode(&m)
	return m, err
}

var ruleID = regexp.MustCompile(`STORE-\d{3}`)

// checkRules reports cited rules that the specification does not define.
func checkRules(m manifest, readme []byte) error {
	defined := map[string]bool{}
	for _, line := range bytes.Split(readme, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("| STORE-")) {
			defined[string(ruleID.Find(line))] = true
		}
	}
	for _, c := range m.Cases {
		for _, r := range c.Rules {
			if !defined[r] {
				return fmt.Errorf("%s cites %s, which README.md does not define", c.ID, r)
			}
		}
	}
	return nil
}

func generate(path string, check bool) error {
	m, err := buildManifest()
	if err != nil {
		return err
	}
	b, err := encodeManifest(m)
	if err != nil {
		return err
	}
	if check {
		old, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(old, b) {
			return fmt.Errorf("%s is stale: run storeconformance generate", path)
		}
		return nil
	}
	return os.WriteFile(path, b, 0o644)
}
