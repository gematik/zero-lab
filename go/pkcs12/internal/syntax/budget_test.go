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

package syntax

import (
	"errors"
	"testing"
)

// TestP12_036TheBudgetCoversAllDerivationsOfOneDecode: every count is within the limit, their
// sum is not.
func TestP12_036TheBudgetCoversAllDerivationsOfOneDecode(t *testing.T) {
	var budget Budget
	for _, step := range []struct {
		iterations, derivations int
		exceeds                 bool
	}{
		{4_000_000, 1, false},
		{4_000_000, 1, false},
		{4_000_000, 1, true},
		{2_000_000, 1, false}, // exactly the budget
		{1, 1, true},
	} {
		err := budget.Spend(step.iterations, step.derivations)
		if errors.Is(err, ErrLimitExceeded) != step.exceeds || (err != nil && !step.exceeds) {
			t.Fatalf("%+v: %v", step, err)
		}
	}
}

// TestP12_036APKCS12PBESpendsItsCountForKeyAndIV: a PKCS#12 PBE derives key and IV.
func TestP12_036APKCS12PBESpendsItsCountForKeyAndIV(t *testing.T) {
	var budget Budget
	if err := budget.Spend(5_000_000, 2); err != nil {
		t.Fatal(err)
	}
	if err := budget.Spend(1, 1); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("err = %v", err)
	}
	if err := new(Budget).Spend(5_000_001, 2); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("err = %v", err)
	}
}

// TestP12_036ACountAboveTheBudgetFailsAndSpendsNothing: a single count above the limit fails
// before anything is derived, and leaves the budget as it was.
func TestP12_036ACountAboveTheBudgetFailsAndSpendsNothing(t *testing.T) {
	var budget Budget
	for _, n := range []int{10_000_001, 1 << 30} {
		if err := budget.Spend(n, 2); !errors.Is(err, ErrLimitExceeded) {
			t.Errorf("%d: err = %v", n, err)
		}
	}
	if err := budget.Spend(10_000_000, 1); err != nil {
		t.Errorf("the budget was spent: %v", err)
	}
}

// TestP12_036AZeroCountIsMalformed.
func TestP12_036AZeroCountIsMalformed(t *testing.T) {
	if err := new(Budget).Spend(0, 1); !errors.Is(err, ErrParse) {
		t.Errorf("err = %v", err)
	}
}
