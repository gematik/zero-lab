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

// Package schema is what the backends of kv share about a database schema that changes in numbered steps:
// which steps are still to apply, and whether a program may work on the schema it finds. It knows no SQL
// and no driver; a backend owns its statements and its table of applied steps.
//
// Steps follow expand, migrate, contract (server rule 22). An expand step adds, and every older program
// keeps working on the result. A contract step removes what older programs still use, so it is applied
// only when asked for, after the last of them is gone.
package schema

import (
	"errors"
	"fmt"
	"slices"
)

// Step is one change of the schema. Versions count from 1 without gaps.
type Step struct {
	Version int
	// Name says what the step does, for logs and errors.
	Name string
	// Contract marks a step that removes something a program of before the step relies on.
	Contract bool
}

// Applied is a step a database records as applied.
type Applied struct {
	Version  int
	Contract bool
}

// Validate reports whether steps are numbered 1, 2, 3, … in order and named.
func Validate(steps []Step) error {
	for i, s := range steps {
		if s.Version != i+1 {
			return fmt.Errorf("kv/schema: step %d has version %d", i+1, s.Version)
		}
		if s.Name == "" {
			return fmt.Errorf("kv/schema: step %d has no name", s.Version)
		}
	}
	return nil
}

// Version is the highest version among applied, 0 for none. It reports an error when the applied steps are
// not 1 to that version without a gap: such a database was not written by these steps.
func Version(applied []Applied) (int, error) {
	seen := make(map[int]bool, len(applied))
	highest := 0
	for _, a := range applied {
		if a.Version < 1 || seen[a.Version] {
			return 0, fmt.Errorf("kv/schema: the database records step %d wrongly", a.Version)
		}
		seen[a.Version] = true
		highest = max(highest, a.Version)
	}
	if len(seen) != highest {
		return 0, fmt.Errorf("kv/schema: the database records %d steps up to version %d", len(seen), highest)
	}
	return highest, nil
}

// Pending returns the steps after version found up to version to (0: all), in order. Without contract it
// stops before the first contract step: what comes after such a step was written for the schema it leaves.
// held is that step when it stopped there.
func Pending(steps []Step, found, to int, contract bool) (pending []Step, held *Step, err error) {
	if err := Validate(steps); err != nil {
		return nil, nil, err
	}
	if to == 0 {
		to = len(steps)
	}
	if to < 0 || to > len(steps) {
		return nil, nil, fmt.Errorf("kv/schema: no step %d: these steps go to %d", to, len(steps))
	}
	if found > len(steps) {
		return nil, nil, nil
	}
	for _, s := range steps[max(found, 0):to] {
		if s.Contract && !contract {
			return pending, &s, nil
		}
		pending = append(pending, s)
	}
	return pending, nil, nil
}

// Needs is the version a program with these steps needs at least: its last step that is not a contract
// step. A contract step it does not need: it works before and after.
func Needs(steps []Step) int {
	for _, s := range slices.Backward(steps) {
		if !s.Contract {
			return s.Version
		}
	}
	return 0
}

// VersionError is a schema a program must not work on.
type VersionError struct {
	// Found is the version of the database, Needs the least the program works on, Knows its last step.
	Found, Needs, Knows int
	// Contract is the applied contract step the program does not know, or 0.
	Contract int
}

// ErrVersion is what every [VersionError] is.
var ErrVersion = errors.New("kv/schema: the schema's version does not fit")

func (e *VersionError) Error() string {
	if e.Contract != 0 {
		return fmt.Sprintf("kv/schema: the database is at version %d and step %d removed something: this program knows steps up to %d and needs a newer release", e.Found, e.Contract, e.Knows)
	}
	return fmt.Sprintf("kv/schema: the database is at version %d, this program needs %d: apply the steps (Migrate, or the option that lets Open do it)", e.Found, e.Needs)
}

// Is reports that the error is an [ErrVersion].
func (e *VersionError) Is(target error) bool { return target == ErrVersion }

// Check reports whether a program with these steps may work on a database with the applied ones (server
// rule 17: it refuses rather than guesses). It may not when a step it needs is missing, nor when a contract
// step it does not know was applied: that step removed something, and the program cannot tell what. Expand
// steps it does not know are fine: during a rollout the next release's steps are applied before the last
// replica of this one is gone (server rule 22).
func Check(steps []Step, applied []Applied) error {
	if err := Validate(steps); err != nil {
		return err
	}
	found, err := Version(applied)
	if err != nil {
		return err
	}
	e := &VersionError{Found: found, Needs: Needs(steps), Knows: len(steps)}
	if found < e.Needs {
		return e
	}
	for _, a := range applied {
		if a.Version > e.Knows && a.Contract && (e.Contract == 0 || a.Version < e.Contract) {
			e.Contract = a.Version
		}
	}
	if e.Contract != 0 {
		return e
	}
	return nil
}
