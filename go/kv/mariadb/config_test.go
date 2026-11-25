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
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/kv/mariadb"
)

// password is a password for a test, made anew for each run.
func password(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestConfig_ADSNIsAnAddressWithTLSUnlessItSaysNot(t *testing.T) {
	secret := password(t)
	addr, database, user, with, tlsOn, params, err := mariadb.Config("mariadb://db.example:3307/store", "kv", secret)
	if err != nil || addr != "db.example:3307" || database != "store" || !tlsOn {
		t.Fatalf("addr %q, database %q, tls %v, err %v", addr, database, tlsOn, err)
	}
	if user != "kv" || with != secret {
		t.Errorf("the driver does not log in with the user and the password given beside the DSN")
	}
	if params["time_zone"] != "'+00:00'" || !strings.Contains(params["sql_mode"], "STRICT_ALL_TABLES") {
		t.Errorf("the session is not in UTC and strict mode: %v", params)
	}
	addr, _, _, _, tlsOn, _, err = mariadb.Config("mariadb://db.example/store?tls=false", "kv", secret)
	if err != nil || addr != "db.example:3306" || tlsOn {
		t.Fatalf("tls=false and no port: addr %q, tls %v, err %v", addr, tlsOn, err)
	}
	if _, _, _, _, tlsOn, _, err := mariadb.Config("mysql://[::1]:3306/store?tls=true", "kv", secret); err != nil || !tlsOn {
		t.Fatalf("the scheme mysql and an IPv6 host: tls %v, err %v", tlsOn, err)
	}
}

// A password is taken as it is: what a URL would read as a delimiter or an escape is part of it.
func TestConfig_APasswordIsNotReadAsPartOfAURL(t *testing.T) {
	for _, secret := range []string{"p@ss:w/rd#?%41", " leading and trailing ", ""} {
		_, _, _, with, _, _, err := mariadb.Config("mariadb://db.example/store", "kv", secret)
		if err != nil || with != secret {
			t.Errorf("a password of %d bytes was changed or refused: %v", len(secret), err)
		}
	}
}

// A DSN is an address. One that carries a user or a password is refused, and the error does not repeat it.
func TestConfig_ADSNWithAUserOrAPasswordIsRefused(t *testing.T) {
	secret := password(t)
	for name, dsn := range map[string]string{
		"a user and a password": "mariadb://kv:" + secret + "@db.example/store",
		"a user alone":          "mariadb://" + secret + "@db.example/store",
		"an empty user":         "mariadb://@db.example/store",
	} {
		if _, _, _, _, _, _, err := mariadb.Config(dsn, "kv", "beside"); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error repeats what the DSN carried: %v", name, err)
		}
	}
}

// Server rule 17: a DSN this backend does not understand in full is refused, not read in part. A parameter
// it does not know may be one that weakens the connection in another driver.
func TestConfig_Rule17RefusesWhatItDoesNotKnow(t *testing.T) {
	for name, dsn := range map[string]string{
		"another scheme":       "postgres://db.example/store",
		"no database":          "mariadb://db.example",
		"no host":              "mariadb:///store",
		"a path below":         "mariadb://db.example/store/more",
		"an unknown parameter": "mariadb://db.example/store?allowAllFiles=true",
		"tls of another word":  "mariadb://db.example/store?tls=skip-verify",
		"not a URL":            "mariadb://db.example:port/store",
	} {
		if _, _, _, _, _, _, err := mariadb.Config(dsn, "kv", "beside"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
