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

package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/tipki/fetch"
	"github.com/gematik/zero-lab/go/tipki/titls"
)

// TLSV-033: each ePA environment is verified over the TSL of its own TI environment, and one without a TSL
// is not started.
func TestTLSV033EachEPAEnvironmentTakesItsTSL(t *testing.T) {
	for env, want := range map[epa.Env]fetch.Environment{
		epa.EnvDev:  fetch.Development,
		epa.EnvTest: fetch.Test,
		epa.EnvRef:  fetch.Reference,
		epa.EnvProd: fetch.Production,
	} {
		if got, err := tslEnvironment(env); err != nil || got != want {
			t.Errorf("%s: %s, %v", env, got, err)
		}
	}
	if _, err := tslEnvironment("staging"); err == nil {
		t.Error("an unknown environment has a TSL")
	}
	if envs := proxyEnvs([]epa.ProxyConfig{{Env: epa.EnvRef}, {Env: epa.EnvDev}, {Env: epa.EnvRef}}); len(envs) != 2 {
		t.Errorf("environments %v", envs)
	}
}

// TLSV-002: a refused Aktensystem is a failure that names the ti profile's reason, as `ti probe` does,
// never a reachable provider.
func TestTLSV002ARefusedAktensystemFailsWithTheProfilesReason(t *testing.T) {
	refused := &titls.RefusedError{Verdict: titls.Verdict{Code: titls.CANotInTSL, Detail: "the issuing CA is not in the TSL"}}
	err := fmt.Errorf("get record status: %w", &url.Error{Op: "Get", URL: "https://epa-as-1.dev.epa4all.de/", Err: refused})
	reason, ok := tlsFailure(err)
	if !ok || reason != "ca_not_in_tsl: the issuing CA is not in the TSL" {
		t.Errorf("%q, %v", reason, ok)
	}
	if _, ok := tlsFailure(errors.New("connection refused")); ok {
		t.Error("a failure without TLS is told as one")
	}
}
