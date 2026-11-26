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

package mariadb_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/mariadb"
)

// A database reached without TLS is refused unless plaintext was accepted: the store does not carry on
// without it. The tests' own database has no TLS for its address, so the default must fail there.
func TestOpen_Rule29ADatabaseIsNotReachedInPlaintextUnlessAccepted(t *testing.T) {
	dsn := testDSN(t)
	if os.Getenv(plaintextEnv) != "true" {
		t.Skip(plaintextEnv + " is not true: the tests' database is not one reached in plaintext")
	}
	ctx := context.Background()
	if s, err := mariadb.Open(ctx, dsn, os.Getenv(userEnv), os.Getenv(passwordEnv)); err == nil {
		_ = s.Close()
		t.Fatal("the store opened without the acceptance of plaintext and without a certificate it could verify")
	}
	if db, err := mariadb.OpenDB(dsn, os.Getenv(userEnv), os.Getenv(passwordEnv)); err != nil {
		t.Fatal(err)
	} else if err := db.PingContext(ctx); err == nil {
		t.Fatal("OpenDB reached the database without the acceptance of plaintext")
	}
	s, err := mariadb.Open(ctx, dsn, os.Getenv(userEnv), os.Getenv(passwordEnv), mariadb.WithPlaintextAccepted())
	if err != nil {
		t.Fatalf("with the acceptance: %v", err)
	}
	_ = s.Close()
}

// tlsDatabase is the address of the tests' database with TLS, and the files of its TEST-ONLY CA and client
// certificate (kv/kvtest/testdata/tls). The database is reached by an address that is not the name of its
// certificate. The user and the password are those of the other tests.
func tlsDatabase(t *testing.T) (dsn string, ca *x509.CertPool, client tls.Certificate) {
	t.Helper()
	dsn, dir := os.Getenv("TEST_MARIADB_TLS_DSN"), os.Getenv("TEST_MARIADB_TLS_DIR")
	if dsn == "" || dir == "" {
		t.Skip("TEST_MARIADB_TLS_DSN and TEST_MARIADB_TLS_DIR not set: skipping the TLS tests of kv/mariadb (just kv-mariadb-test)")
	}
	pem, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca = x509.NewCertPool()
	if !ca.AppendCertsFromPEM(pem) {
		t.Fatal("the CA file holds no certificate")
	}
	client, err = tls.LoadX509KeyPair(filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return dsn, ca, client
}

const tlsServerName = "kv-test-db"

// Server rule 29: the server's certificate is verified, for its CA and for its name. A CA of the
// deployment's own comes with WithTLS.
func TestOpen_Rule29TheServersCertificateIsVerifiedForItsCAAndItsName(t *testing.T) {
	ctx := context.Background()
	dsn, ca, _ := tlsDatabase(t)
	user, password := os.Getenv(userEnv), os.Getenv(passwordEnv)
	good := &tls.Config{RootCAs: ca, ServerName: tlsServerName, MinVersion: tls.VersionTLS12}
	db, err := mariadb.OpenDB(dsn, user, password, mariadb.WithTLS(good))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := mariadb.Migrate(ctx, db); err != nil {
		t.Fatalf("with the CA and the name of the certificate: %v", err)
	}
	var name, cipher string
	if err := db.QueryRowContext(ctx, `SHOW SESSION STATUS LIKE 'Ssl_cipher'`).Scan(&name, &cipher); err != nil || cipher == "" {
		t.Fatalf("the database says the connection's cipher is %q, err %v", cipher, err)
	}

	for name, config := range map[string]*tls.Config{
		"the system's roots, which do not know the CA": nil,
		"the CA, and the address as the name":          {RootCAs: ca, MinVersion: tls.VersionTLS12},
		"the CA, and another name":                     {RootCAs: ca, ServerName: "another-db", MinVersion: tls.VersionTLS12},
		"another CA, and the name":                     {RootCAs: x509.NewCertPool(), ServerName: tlsServerName, MinVersion: tls.VersionTLS12},
	} {
		var opts []mariadb.Option
		if config != nil {
			opts = append(opts, mariadb.WithTLS(config))
		}
		if s, err := mariadb.Open(ctx, dsn, user, password, opts...); err == nil {
			_ = s.Close()
			t.Errorf("%s: the store opened", name)
		}
	}

	s, err := mariadb.Open(ctx, dsn, user, password, mariadb.WithTLS(good))
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
}

// A user the database lets in only with a client certificate: WithTLS carries the certificate.
func TestOpen_Rule29AClientCertificateIsPresentedWhenTheConfigurationHasOne(t *testing.T) {
	ctx := context.Background()
	dsn, ca, client := tlsDatabase(t)
	without := &tls.Config{RootCAs: ca, ServerName: tlsServerName, MinVersion: tls.VersionTLS12}
	if s, err := mariadb.Open(ctx, dsn, "kv_mtls", "test-only", mariadb.WithTLS(without)); err == nil {
		_ = s.Close()
		t.Fatal("the user that needs a client certificate was let in without one")
	}
	with := without.Clone()
	with.Certificates = []tls.Certificate{client}
	s, err := mariadb.Open(ctx, dsn, "kv_mtls", "test-only", mariadb.WithTLS(with))
	if err != nil {
		t.Fatalf("with the client certificate: %v", err)
	}
	_ = s.Close()
}
