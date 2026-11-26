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
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// transport is how a store reaches its database: with TLS, which is the default, or in plaintext that the
// operator accepted (server rule 29). It is never both and never one falling back to the other.
type transport struct {
	// tls is a configuration of the host's own, for a server whose certificate the system's roots do not
	// vouch for, or to present a client certificate.
	tls *tls.Config
	// plaintext is the operator's acceptance of a connection without TLS.
	plaintext bool
}

// tlsCurves are the curves offered to the database: the NIST curves gemSpec_Krypt names for TLS, which
// every server of an internet or a deployment PKI has.
var tlsCurves = []tls.CurveID{tls.CurveP256, tls.CurveP384}

// config is the TLS configuration of a connection to host, or nil for accepted plaintext.
func (t transport) config(host string) (*tls.Config, error) {
	if t.plaintext {
		if t.tls != nil {
			return nil, errors.New("kv/postgres: a TLS configuration beside accepted plaintext")
		}
		return nil, nil
	}
	if t.tls == nil {
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, CurvePreferences: tlsCurves}, nil
	}
	if t.tls.InsecureSkipVerify {
		return nil, errors.New("kv/postgres: a TLS configuration that skips verification")
	}
	cfg := t.tls.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		cfg.MinVersion = tls.VersionTLS12
	}
	return cfg, nil
}

// poolConfig makes the driver's configuration from a DSN of the form
//
//	postgres://host:port/database
//
// and from the user and the password, which are not part of it: a DSN is an address, written into
// configuration and logs, and a password in a URL has to be escaped to be read as it is meant. A DSN that
// carries a user or a password is refused, and so is one with any parameter, as in kv/mariadb: a parameter
// would set the session, name another host or say how the connection is protected, and nothing in an
// address may weaken the connection or the durability of a write. So is one that is not a URL. The connection is TLS, with the
// server's certificate verified for the host of the DSN, unless the transport says the operator accepted
// plaintext; the driver's own modes that try one and fall back to the other are not used. What the driver
// would otherwise take from the environment or from files in the user's home (PGUSER, PGPASSWORD,
// PGSSLMODE, a password file, a service file) is not used either.
func poolConfig(dsn, user, password string, t transport) (*pgxpool.Config, error) {
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
	// A parameter of a connection URL sets the session (synchronous_commit, search_path, options), names
	// another host, a user, a password or a file that holds one, or says how the connection is protected:
	// each is the store's or the host's to say, not the address's. So there is none.
	for name := range u.Query() {
		return nil, fmt.Errorf("kv/postgres: the DSN has a parameter, %s: it is the address alone", name)
	}
	if u.Hostname() == "" {
		return nil, errors.New("kv/postgres: the DSN names no host")
	}
	if user == "" {
		return nil, errors.New("kv/postgres: no user")
	}
	tlsConfig, err := t.config(u.Hostname())
	if err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: the DSN: %w", err)
	}
	cfg.ConnConfig.User = user
	cfg.ConnConfig.Password = password
	// One way to connect and no other to fall back to: the driver's own ones, made from its default mode
	// or from PGSSLMODE, go.
	cfg.ConnConfig.TLSConfig = tlsConfig
	cfg.ConnConfig.Fallbacks = nil
	return cfg, nil
}

// WithTLS sets the TLS configuration of the connections: a CA of the deployment's own, a client
// certificate. Without it the server's certificate is verified against the system's roots. The name the
// certificate is verified for is the host of the DSN unless the configuration names another. A
// configuration that skips verification is refused.
func WithTLS(config *tls.Config) Option {
	return func(s *store) { s.transport.tls = config }
}

// WithPlaintextAccepted lets the store connect without TLS: the operator's statement that the deployment
// protects the connection (server rule 29). A host sets it from a setting of its own beside the DSN, never
// by default; the backend logs it at Open. Without it a database that offers no TLS is refused.
func WithPlaintextAccepted() Option {
	return func(s *store) { s.transport.plaintext = true }
}

func transportOf(opts []Option) transport {
	s := &store{}
	for _, opt := range opts {
		opt(s)
	}
	return s.transport
}

// logPlaintext says at Open that a connection is in plaintext by the operator's acceptance.
func logPlaintext(ctx context.Context, what string, t transport, cfg *pgxpool.Config) {
	if t.plaintext {
		slog.WarnContext(ctx, "kv/postgres: "+what+" is in plaintext, accepted by the operator",
			"host", cfg.ConnConfig.Host, "database", cfg.ConnConfig.Database)
	}
}

// OpenDB opens connections to the database of dsn as user: for [Migrate], which takes a role that may
// change the schema. Of the options it takes [WithTLS] and [WithPlaintextAccepted].
func OpenDB(dsn, user, password string, opts ...Option) (*sql.DB, error) {
	cfg, err := poolConfig(dsn, user, password, transportOf(opts))
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
