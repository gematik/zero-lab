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
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/tipki"
	"github.com/gematik/zero-lab/go/tipki/fetch"
	"github.com/gematik/zero-lab/go/tipki/titls"
)

// tiHTTPTimeout bounds each download of the TSL and each OCSP request about an Aktensystem.
const tiHTTPTimeout = 30 * time.Second

// tiTrust is the ti profile for the Aktensysteme of each environment the process reaches: a TSL it
// downloads and keeps fresh itself, and the verifier over it.
type tiTrust struct {
	trusts  []*fetch.Trust
	configs map[epa.Env]*tls.Config
}

// newTiTrust fetches the TSL of each of envs; a failure fails the start with the reason. The TSL hosts are
// on the internet and verified under the web profile.
func newTiTrust(envs ...epa.Env) (*tiTrust, error) {
	webClient, err := titls.NewWebHTTPClient(tiHTTPTimeout, titls.Options{})
	if err != nil {
		return nil, fmt.Errorf("the TSL hosts' TLS: %w", err)
	}
	t := &tiTrust{configs: make(map[epa.Env]*tls.Config)}
	for _, env := range envs {
		if _, ok := t.configs[env]; ok {
			continue
		}
		tslEnv, err := tslEnvironment(env)
		if err != nil {
			t.Close()
			return nil, err
		}
		trust, err := fetch.New(tslEnv, webClient)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("the TI trust material of %s: %w", env, err)
		}
		t.trusts = append(t.trusts, trust)
		responder := tipki.NewOCSPChecker(titls.OCSPTransport(titls.NewHTTPFetcher(&http.Client{Timeout: tiHTTPTimeout})))
		t.configs[env] = titls.NewTiVerifier(trust.Source(), responder, titls.Options{}).ClientConfig()
	}
	return t, nil
}

// config is the ti configuration for the Aktensysteme of env.
func (t *tiTrust) config(env epa.Env) *tls.Config {
	return t.configs[env]
}

// Close stops refreshing the TSLs.
func (t *tiTrust) Close() {
	for _, trust := range t.trusts {
		trust.Close()
	}
}

// tslEnvironment is the TSL of an ePA environment; fetch's development environment takes the reference
// environment's material.
func tslEnvironment(env epa.Env) (fetch.Environment, error) {
	switch env {
	case epa.EnvDev:
		return fetch.Development, nil
	case epa.EnvTest:
		return fetch.Test, nil
	case epa.EnvRef:
		return fetch.Reference, nil
	case epa.EnvProd:
		return fetch.Production, nil
	default:
		return "", fmt.Errorf("no TSL for the ePA environment %q", env)
	}
}

// proxyEnvs are the environments of configs, each once.
func proxyEnvs(configs []epa.ProxyConfig) []epa.Env {
	var envs []epa.Env
	for _, config := range configs {
		if !slices.Contains(envs, config.Env) {
			envs = append(envs, config.Env)
		}
	}
	return envs
}

// tlsFailure is why a TLS connection failed, if it did: the ti profile's verdict when it refused the server.
func tlsFailure(err error) (string, bool) {
	if refused, ok := errors.AsType[*titls.RefusedError](err); ok {
		return string(refused.Verdict.Code) + ": " + refused.Verdict.Detail, true
	}
	if verification, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return verification.Err.Error(), true
	}
	if alert, ok := errors.AsType[tls.AlertError](err); ok {
		return "the server sent " + alert.Error(), true
	}
	return "", false
}
