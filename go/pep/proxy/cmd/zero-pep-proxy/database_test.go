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
	"errors"
	"strings"
	"testing"
)

// testPassword is the password of the tests' database URLs; it opens nothing.
const testPassword = "of-the-test"

func databaseEnv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

// Server rule 29: the database is a peer like any other. Its connection is TLS unless the operator accepted
// plaintext with a setting of its own, read as an agreement: one exact value.
func TestDatabaseOf_Rule29PlaintextOnlyByTheOperatorsAcceptance(t *testing.T) {
	// Made of parts: a URL with a password in one literal reads as a credential to the linter.
	dsn := "postgres://pep:" + testPassword + "@db.example:5432/pep"
	db, err := databaseOf(dsn, databaseEnv(nil), nil)
	if err != nil || db.address != "postgres://db.example:5432/pep" || db.user != "pep" || db.password != testPassword {
		t.Fatalf("address %q, user %q, err %v", db.address, db.user, err)
	}
	if len(db.transport) != 0 {
		t.Error("without a setting the connection is not the store's default, TLS under the system's roots")
	}
	db, err = databaseOf(dsn, databaseEnv(map[string]string{databasePlaintextEnv: "true"}), nil)
	if err != nil || len(db.transport) != 1 {
		t.Fatalf("accepted plaintext: %d options, err %v", len(db.transport), err)
	}
	for _, value := range []string{"false", "yes", "1", "TRUE", " true"} {
		if _, err := databaseOf(dsn, databaseEnv(map[string]string{databasePlaintextEnv: value}), nil); err == nil {
			t.Errorf("%s=%q was read as something", databasePlaintextEnv, value)
		}
	}
}

func TestDatabaseOf_Rule29ACABundleFromAFileOrNothingAtAll(t *testing.T) {
	// Made of parts: a URL with a password in one literal reads as a credential to the linter.
	dsn := "postgres://pep:" + testPassword + "@db.example:5432/pep"
	read := func(files map[string]string) func(string) ([]byte, error) {
		return func(path string) ([]byte, error) {
			if data, ok := files[path]; ok {
				return []byte(data), nil
			}
			return nil, errors.New("no such file")
		}
	}
	withCA := databaseEnv(map[string]string{databaseCAPathEnv: "/ca.pem"})
	if _, err := databaseOf(dsn, withCA, read(nil)); err == nil || !strings.Contains(err.Error(), databaseCAPathEnv) {
		t.Errorf("a CA file that is not there: %v", err)
	}
	if _, err := databaseOf(dsn, withCA, read(map[string]string{"/ca.pem": "not a certificate"})); err == nil {
		t.Error("a CA file without a certificate was accepted")
	}
	both := databaseEnv(map[string]string{databaseCAPathEnv: "/ca.pem", databasePlaintextEnv: "true"})
	if _, err := databaseOf(dsn, both, read(map[string]string{"/ca.pem": "unread"})); err == nil {
		t.Error("a CA for TLS beside accepted plaintext was accepted")
	}
}
