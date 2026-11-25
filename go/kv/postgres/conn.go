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

package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// credentialParameters are the parameters of a connection URL that name a user or a password, or a file
// that holds them.
var credentialParameters = []string{"user", "password", "passfile", "service", "servicefile"}

// poolConfig makes the driver's configuration from a DSN of the form
//
//	postgres://host:port/database?sslmode=verify-full
//
// and from the user and the password, which are not part of it: a DSN is an address, written into
// configuration and logs, and a password in a URL has to be escaped to be read as it is meant. A DSN that
// carries a user or a password, as part of the URL or as a parameter, is refused; so is one that is not a
// URL. What the driver would otherwise take from the environment or from files in the user's home
// (PGUSER, PGPASSWORD, a password file, a service file) is not used: the two given here are what it logs
// in with.
func poolConfig(dsn, user, password string) (*pgxpool.Config, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		// What is not a URL may still hold a secret someone put there: the parse error, which quotes it,
		// is not passed on.
		return nil, errors.New("kv/postgres: the DSN is not a URL")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, errors.New("kv/postgres: the DSN's scheme is not postgres")
	}
	if u.User != nil {
		return nil, errors.New("kv/postgres: the DSN carries a user or a password: they are given beside it")
	}
	query := u.Query()
	for _, name := range credentialParameters {
		if query.Has(name) {
			return nil, fmt.Errorf("kv/postgres: the DSN names %s: user and password are given beside it", name)
		}
	}
	if user == "" {
		return nil, errors.New("kv/postgres: no user")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: the DSN: %w", err)
	}
	cfg.ConnConfig.User = user
	cfg.ConnConfig.Password = password
	return cfg, nil
}

// OpenDB opens connections to the database of dsn as user: for [Migrate], which takes a role that may
// change the schema.
func OpenDB(dsn, user, password string) (*sql.DB, error) {
	cfg, err := poolConfig(dsn, user, password)
	if err != nil {
		return nil, err
	}
	return stdlib.OpenDB(*cfg.ConnConfig), nil
}

// SplitURL takes a connection URL that carries a user and a password apart: the address, as [Open] takes
// it, and the two beside it. It is for a host whose configuration still holds one URL with everything in
// it. A URL without a user comes back as it is.
func SplitURL(dsn string) (address, user, password string, err error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", "", "", errors.New("kv/postgres: the DSN is not a URL")
	}
	if u.User != nil {
		user = u.User.Username()
		password, _ = u.User.Password()
		u.User = nil
	}
	return u.String(), user, password, nil
}
