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
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestManifestIsCurrent(t *testing.T) {
	m, err := buildManifest()
	if err != nil {
		t.Fatal(err)
	}
	want, err := encodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testdata/manifest.json is stale: run go run . generate")
	}
}

func TestEveryCitedRuleIsDefined(t *testing.T) {
	m, err := readManifest("../testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRules(m, readme); err != nil {
		t.Fatal(err)
	}
}

// answers runs the reference adapter over the whole manifest in process.
func answers(t *testing.T, m manifest) [][]byte {
	t.Helper()
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, c := range m.Cases {
		if err := enc.Encode(request{ID: c.ID, Kind: c.Kind, Input: c.Input}); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := serve(&in, &out); err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	sc := bufio.NewScanner(&out)
	sc.Buffer(nil, maxLine)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	if len(lines) != len(m.Cases) {
		t.Fatalf("%d answers for %d cases", len(lines), len(m.Cases))
	}
	return lines
}

func TestReferenceAdapterPassesEveryCase(t *testing.T) {
	m, err := readManifest("../testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range answers(t, m) {
		if o := judge(m.Cases[i], line); o.verdict != "pass" {
			t.Errorf("%s: %s %s", o.id, o.verdict, o.detail)
		}
	}
}

// A verifier that passes everything proves nothing: wrong codes, wrong bytes, answers out
// of order and unsupported kinds must each be told apart.
func TestVerifierRejectsWrongAnswers(t *testing.T) {
	m, err := readManifest("../testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	lines := answers(t, m)
	find := func(id string) (manifestCase, []byte) {
		for i, c := range m.Cases {
			if c.ID == id {
				return c, lines[i]
			}
		}
		t.Fatalf("no case %s", id)
		return manifestCase{}, nil
	}

	c, line := find("open-flipped-tag")
	if o := judge(c, bytes.Replace(line, []byte("auth_failed"), []byte("malformed"), 1)); o.verdict != "fail" {
		t.Error("a wrong code passed")
	}
	c, line = find("seal-basic")
	var r response
	if err := json.Unmarshal(line, &r); err != nil {
		t.Fatal(err)
	}
	rec := r.Output["record"].(string)
	last := "0"
	if strings.HasSuffix(rec, "0") {
		last = "1"
	}
	r.Output["record"] = rec[:len(rec)-1] + last
	changed, _ := json.Marshal(r)
	if o := judge(c, changed); o.verdict != "fail" {
		t.Error("a changed record passed")
	}
	other, _ := find("seal-no-expiry")
	if o := judge(other, line); o.verdict != "fail" {
		t.Error("an answer for another case passed")
	}
	if o := judge(c, []byte(`{"id":"seal-basic","code":"unsupported"}`)); o.verdict != "skip" {
		t.Error("unsupported was not reported as a skip")
	}
	if o := judge(c, []byte(`{"id":"seal-basic","code":"ok","output":{}}`)); o.verdict != "fail" {
		t.Error("an empty output passed")
	}
}
