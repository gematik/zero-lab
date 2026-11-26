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

package postgres_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/postgres"
)

// Server rule 29: a database is reached with TLS, its certificate verified for the host of the DSN, and in
// no other way the driver would fall back to, whatever the environment says.
func TestConfig_Rule29TheConnectionIsTLSWithoutAFallback(t *testing.T) {
	for _, mode := range []string{"", "disable", "prefer", "allow"} {
		t.Setenv("PGSSLMODE", mode)
		withTLS, name, fallbacks, err := postgres.Transport("postgres://db.example:5433/store")
		if err != nil || !withTLS || name != "db.example" || fallbacks != 0 {
			t.Errorf("PGSSLMODE=%q: tls %v, verified for %q, %d fallbacks, err %v", mode, withTLS, name, fallbacks, err)
		}
	}
}

// Server rule 29: plaintext is the operator's explicit acceptance, an option the host sets, and nothing in
// the address can stand in for it or weaken the connection.
func TestConfig_Rule29PlaintextOnlyWhenAccepted(t *testing.T) {
	const dsn = "postgres://db.example/store"
	t.Setenv("PGSSLMODE", "verify-full")
	if withTLS, _, fallbacks, err := postgres.Transport(dsn, postgres.WithPlaintextAccepted()); err != nil || withTLS || fallbacks != 0 {
		t.Fatalf("accepted plaintext: tls %v, %d fallbacks, err %v", withTLS, fallbacks, err)
	}
	for _, parameter := range []string{"sslmode=disable", "sslmode=prefer", "sslmode=require", "sslmode=verify-full", "sslrootcert=/ca.pem", "sslcert=/c.pem", "sslkey=/k.pem", "sslnegotiation=direct", "gssencmode=disable", "channel_binding=disable"} {
		if _, _, _, err := postgres.Transport(dsn + "?" + parameter); err == nil {
			t.Errorf("%s in the DSN: accepted", parameter)
		}
	}
	own := &tls.Config{MinVersion: tls.VersionTLS12}
	if _, name, _, err := postgres.Transport(dsn, postgres.WithTLS(own)); err != nil || name != "db.example" {
		t.Errorf("a configuration of the host's own without a name is verified for %q, err %v", name, err)
	}
	if _, name, _, err := postgres.Transport(dsn, postgres.WithTLS(&tls.Config{ServerName: "db.internal", MinVersion: tls.VersionTLS12})); err != nil || name != "db.internal" {
		t.Errorf("a configuration that names the server is verified for %q, err %v", name, err)
	}
	if _, _, _, err := postgres.Transport(dsn, postgres.WithTLS(&tls.Config{InsecureSkipVerify: true})); err == nil { //nolint:gosec // G402: the configuration that is refused
		t.Error("a configuration that skips verification: accepted")
	}
	if _, _, _, err := postgres.Transport(dsn, postgres.WithTLS(own), postgres.WithPlaintextAccepted()); err == nil {
		t.Error("a TLS configuration beside accepted plaintext: accepted")
	}
}

// A database without TLS is refused unless plaintext was accepted: the store does not try TLS and carry on
// without it.
func TestOpen_Rule29ADatabaseWithoutTLSIsRefusedUnlessPlaintextIsAccepted(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping Postgres kv test (see pdp/docker-compose.yaml)")
	}
	ctx := context.Background()
	address, user, password, _, err := apart(dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := postgres.Open(ctx, address, user, password); err == nil {
		_ = s.Close()
		t.Fatal("the store opened a database that offers no TLS without the acceptance of plaintext")
	}
	if _, err := postgres.OpenBus(ctx, address, user, password); err == nil {
		t.Fatal("the bus opened a database that offers no TLS without the acceptance of plaintext")
	}
	if db, err := postgres.OpenDB(address, user, password); err != nil {
		t.Fatal(err)
	} else if err := db.PingContext(ctx); err == nil {
		t.Fatal("OpenDB reached a database that offers no TLS without the acceptance of plaintext")
	}
	s, err := postgres.Open(ctx, address, user, password, postgres.WithPlaintextAccepted())
	if err != nil {
		t.Fatalf("with the acceptance: %v", err)
	}
	_ = s.Close()
}

// tlsDatabase is the address of the tests' database with TLS, the user and the password, and the files of
// its TEST-ONLY CA and client certificate (kv/kvtest/testdata/tls). The database is reached by an address
// that is not the name of its certificate.
func tlsDatabase(t *testing.T) (address, user, password string, ca *x509.CertPool, client tls.Certificate) {
	t.Helper()
	dsn, dir := os.Getenv("TEST_DATABASE_TLS_URL"), os.Getenv("TEST_DATABASE_TLS_DIR")
	if dsn == "" || dir == "" {
		t.Skip("TEST_DATABASE_TLS_URL and TEST_DATABASE_TLS_DIR not set: skipping the TLS tests of kv/postgres (just kv-postgres-test)")
	}
	address, user, password, err := postgres.SplitURL(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// The files are read within the directory the variable names, and nowhere else.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	read := func(name string) []byte {
		data, err := root.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	ca = x509.NewCertPool()
	if !ca.AppendCertsFromPEM(read("ca.pem")) {
		t.Fatal("the CA file holds no certificate")
	}
	client, err = tls.X509KeyPair(read("client.pem"), read("client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return address, user, password, ca, client
}

const tlsServerName = "kv-test-db"

// Server rule 29: the server's certificate is verified, for its CA and for its name. A CA of the
// deployment's own comes with WithTLS.
func TestOpen_Rule29TheServersCertificateIsVerifiedForItsCAAndItsName(t *testing.T) {
	ctx := context.Background()
	address, user, password, ca, _ := tlsDatabase(t)
	db, err := postgres.OpenDB(address, user, password, postgres.WithTLS(&tls.Config{RootCAs: ca, ServerName: tlsServerName, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := postgres.Migrate(ctx, db); err != nil {
		t.Fatalf("with the CA and the name of the certificate: %v", err)
	}
	var withTLS bool
	if err := db.QueryRowContext(ctx, `SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()`).Scan(&withTLS); err != nil || !withTLS {
		t.Fatalf("the database says the connection is TLS: %v, err %v", withTLS, err)
	}

	for name, config := range map[string]*tls.Config{
		"the system's roots, which do not know the CA": nil,
		"the CA, and the address as the name":          {RootCAs: ca, MinVersion: tls.VersionTLS12},
		"the CA, and another name":                     {RootCAs: ca, ServerName: "another-db", MinVersion: tls.VersionTLS12},
		"another CA, and the name":                     {RootCAs: x509.NewCertPool(), ServerName: tlsServerName, MinVersion: tls.VersionTLS12},
	} {
		var opts []postgres.Option
		if config != nil {
			opts = append(opts, postgres.WithTLS(config))
		}
		if s, err := postgres.Open(ctx, address, user, password, opts...); err == nil {
			_ = s.Close()
			t.Errorf("%s: the store opened", name)
		}
	}

	s, err := postgres.Open(ctx, address, user, password, postgres.WithTLS(&tls.Config{RootCAs: ca, ServerName: tlsServerName, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key := "tls:" + time.Now().Format(time.RFC3339Nano)
	if err := s.Set(ctx, key, []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.(kv.Transactor).Tx(ctx, func(tx kv.Tx) error { return tx.Delete(ctx, key) }); err != nil {
		t.Fatal(err)
	}
	// The follower's own connection and the bus are made from the same configuration.
	follow, cancel := context.WithCancel(ctx)
	defer cancel()
	events, err := s.(kv.Feed).Follow(follow, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := s.(kv.Feed).Publish(ctx, key, []byte("e"), time.Minute); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-events:
		if e.Cursor != 1 {
			t.Fatalf("number %d", e.Cursor)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the follower's connection over TLS delivered no event")
	}
	bus, err := postgres.OpenBus(ctx, address, user, password, postgres.WithTLS(&tls.Config{RootCAs: ca, ServerName: tlsServerName, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatalf("the bus over TLS: %v", err)
	}
	_ = bus.Close()
}

// A role the database lets in only with a client certificate: WithTLS carries the certificate.
func TestOpen_Rule29AClientCertificateIsPresentedWhenTheConfigurationHasOne(t *testing.T) {
	ctx := context.Background()
	address, _, _, ca, client := tlsDatabase(t)
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	without := &tls.Config{RootCAs: ca, ServerName: tlsServerName, MinVersion: tls.VersionTLS12}
	if s, err := postgres.Open(ctx, u.String(), "kv_mtls", "test-only", postgres.WithTLS(without)); err == nil {
		_ = s.Close()
		t.Fatal("the role that needs a client certificate was let in without one")
	}
	with := without.Clone()
	with.Certificates = []tls.Certificate{client}
	s, err := postgres.Open(ctx, u.String(), "kv_mtls", "test-only", postgres.WithTLS(with))
	if err != nil {
		t.Fatalf("with the client certificate: %v", err)
	}
	_ = s.Close()
}
