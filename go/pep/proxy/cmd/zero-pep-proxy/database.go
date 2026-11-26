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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/gematik/zero-lab/go/kv/postgres"
)

// The variables of the connection to the database (servers.md rule 29, naming-and-config.md), beside
// PEP_DATABASE_URL.
const (
	databasePlaintextEnv = "PEP_DATABASE_PLAINTEXT_ACCEPTED"
	databaseCAPathEnv    = "PEP_DATABASE_TLS_CA_PATH"
)

// database is where the store and the revocation bus are and how they are reached.
type database struct {
	address, user, password string
	// transport is how the connection is protected: TLS under the system's roots when it is empty.
	transport []postgres.Option
}

// databaseOf reads the peer from PEP_DATABASE_URL, one URL with the user and the password in it, which the
// store takes apart, and how the connection is protected from the variables beside it. The connection is
// TLS with the server's certificate verified: under the system's roots, or under the CA bundle of
// PEP_DATABASE_TLS_CA_PATH. Plaintext is the operator's acceptance, PEP_DATABASE_PLAINTEXT_ACCEPTED=true, as
// for the listener; the URL itself says nothing of it, and one that names sslmode is refused by the store.
func databaseOf(dsn string, getenv func(string) string, readFile func(string) ([]byte, error)) (database, error) {
	address, user, password, err := postgres.SplitURL(dsn)
	if err != nil {
		return database{}, err
	}
	db := database{address: address, user: user, password: password}
	accepted, caPath := getenv(databasePlaintextEnv), getenv(databaseCAPathEnv)
	switch {
	case accepted != "" && accepted != "true":
		return database{}, fmt.Errorf("%s: true, or not set", databasePlaintextEnv)
	case accepted == "true" && caPath != "":
		return database{}, fmt.Errorf("%s accepts plaintext and %s names a CA for TLS: unset one", databasePlaintextEnv, databaseCAPathEnv)
	case accepted == "true":
		db.transport = []postgres.Option{postgres.WithPlaintextAccepted()}
	case caPath != "":
		pem, err := readFile(caPath)
		if err != nil {
			return database{}, fmt.Errorf("%s: %w", databaseCAPathEnv, err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return database{}, errors.New(databaseCAPathEnv + ": the file holds no certificate")
		}
		db.transport = []postgres.Option{postgres.WithTLS(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})}
	}
	return db, nil
}

// readOperatorFile reads a file the operator's configuration names.
func readOperatorFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
