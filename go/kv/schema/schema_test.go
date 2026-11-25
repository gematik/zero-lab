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

package schema_test

import (
	"errors"
	"testing"

	"github.com/gematik/zero-lab/go/kv/schema"
)

var steps = []schema.Step{
	{Version: 1, Name: "the table"},
	{Version: 2, Name: "a column more"},
	{Version: 3, Name: "the old column goes", Contract: true},
	{Version: 4, Name: "an index"},
}

func applied(contract map[int]bool, versions ...int) []schema.Applied {
	var out []schema.Applied
	for _, v := range versions {
		out = append(out, schema.Applied{Version: v, Contract: contract[v]})
	}
	return out
}

func TestValidate_StepsCountFromOneWithoutGaps(t *testing.T) {
	if err := schema.Validate(steps); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]schema.Step{
		"a gap":         {{Version: 1, Name: "a"}, {Version: 3, Name: "c"}},
		"begins at two": {{Version: 2, Name: "b"}},
		"no name":       {{Version: 1}},
	} {
		if schema.Validate(bad) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPending_StopsBeforeAContractStepUnlessAsked(t *testing.T) {
	pending, held, err := schema.Pending(steps, 0, 0, false)
	if err != nil || len(pending) != 2 || held == nil || held.Version != 3 {
		t.Fatalf("pending %v, held %v, err %v", pending, held, err)
	}
	pending, held, err = schema.Pending(steps, 0, 0, true)
	if err != nil || len(pending) != 4 || held != nil {
		t.Fatalf("with contract: pending %v, held %v, err %v", pending, held, err)
	}
	pending, held, err = schema.Pending(steps, 2, 0, false)
	if err != nil || len(pending) != 0 || held == nil {
		t.Fatalf("at 2: pending %v, held %v, err %v", pending, held, err)
	}
	pending, _, err = schema.Pending(steps, 1, 2, true)
	if err != nil || len(pending) != 1 || pending[0].Version != 2 {
		t.Fatalf("to 2: pending %v, err %v", pending, err)
	}
	if _, _, err := schema.Pending(steps, 0, 9, true); err == nil {
		t.Error("a step that is not there was accepted as the aim")
	}
	if pending, _, err := schema.Pending(steps, 7, 0, true); err != nil || len(pending) != 0 {
		t.Errorf("a database ahead of the steps: pending %v, err %v", pending, err)
	}
}

func TestCheck_Rule17RefusesASchemaWithAMissingStep(t *testing.T) {
	err := schema.Check(steps, applied(nil, 1, 2))
	var v *schema.VersionError
	if !errors.As(err, &v) || !errors.Is(err, schema.ErrVersion) {
		t.Fatalf("got %v", err)
	}
	if v.Found != 2 || v.Needs != 4 || v.Knows != 4 {
		t.Errorf("found %d, needs %d, knows %d", v.Found, v.Needs, v.Knows)
	}
	if schema.Check(steps, nil) == nil {
		t.Error("an empty database was accepted")
	}
}

func TestCheck_Rule22AcceptsExpandStepsOfANewerRelease(t *testing.T) {
	older := steps[:2]
	if err := schema.Check(older, applied(nil, 1, 2, 3, 4)); err != nil {
		t.Errorf("unknown expand steps refused: %v", err)
	}
}

func TestCheck_Rule17RefusesAContractStepItDoesNotKnow(t *testing.T) {
	older := steps[:2]
	err := schema.Check(older, applied(map[int]bool{3: true}, 1, 2, 3, 4))
	var v *schema.VersionError
	if !errors.As(err, &v) || v.Contract != 3 || v.Found != 4 || v.Knows != 2 {
		t.Fatalf("got %v", err)
	}
}

func TestCheck_AcceptsItsOwnContractStepAppliedOrNot(t *testing.T) {
	own := steps[:3]
	if err := schema.Check(own, applied(nil, 1, 2)); err != nil {
		t.Errorf("before its contract step: %v", err)
	}
	if err := schema.Check(own, applied(map[int]bool{3: true}, 1, 2, 3)); err != nil {
		t.Errorf("after its contract step: %v", err)
	}
}

func TestVersion_RefusesADatabaseWithAGapOrADuplicate(t *testing.T) {
	if _, err := schema.Version(applied(nil, 1, 3)); err == nil {
		t.Error("a gap was accepted")
	}
	if _, err := schema.Version(applied(nil, 1, 1)); err == nil {
		t.Error("a duplicate was accepted")
	}
	if v, err := schema.Version(nil); err != nil || v != 0 {
		t.Errorf("empty: %d, %v", v, err)
	}
}
