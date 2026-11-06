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

package epatest

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
	"github.com/gematik/zero-lab/go/tipki/fetch"
	"github.com/gematik/zero-lab/go/tipki/titls"
)

// TiTLSConfig verifies the Aktensysteme of env (dev, test, ref or prod) under the ti profile, over the TSL
// it downloads for the test, as zero-epa does at its start. For the gated live tests: it needs gematik's
// TSL hosts.
func TiTLSConfig(tb testing.TB, env string) *tls.Config {
	tb.Helper()
	tslEnv, err := fetch.ParseEnvironment(env)
	if err != nil {
		tb.Fatal(err)
	}
	webClient, err := titls.NewWebHTTPClient(30*time.Second, titls.Options{})
	if err != nil {
		tb.Fatal(err)
	}
	trust, err := fetch.New(tslEnv, webClient)
	if err != nil {
		tb.Fatalf("the TI trust material of %s: %v", env, err)
	}
	tb.Cleanup(trust.Close)
	responder := tipki.NewOCSPChecker(titls.OCSPTransport(titls.NewHTTPFetcher(&http.Client{Timeout: 30 * time.Second})))
	return titls.NewTiVerifier(trust.Source(), responder, titls.Options{}).ClientConfig()
}
