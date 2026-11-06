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

package idpd

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/gematik/zero-lab/go/tipki/fetch"
)

// FetchingTrust downloads its trust material, for a deployment that has no producer to mount a bundle from
// (decision-12), through [fetch.Trust]. Nothing it downloads is trusted for where it came from: it passes the
// checks a bundle passes, and a list is taken only under the hash the HTTPS host names (IDPV-007).
//
// It fetches at the start, which must succeed, and then in the background: a login only reads the copy in
// memory, which stands for [tipki.MaxBundleAge] from its last good refresh, and after that refuses (IDPV-008).
type FetchingTrust struct {
	verifier
	trust *fetch.Trust
}

// NewFetchingTrust fetches once, so a deployment without a route to the material does not start, and keeps
// refreshing until [FetchingTrust.Close]. httpClient carries the downloads and OCSP.
func NewFetchingTrust(env Environment, httpClient *http.Client) (*FetchingTrust, error) {
	base, err := newVerifier(env, httpClient)
	if err != nil {
		return nil, err
	}
	trust, err := fetch.New(fetchEnvironment(env), httpClient)
	if err != nil {
		return nil, err
	}
	return &FetchingTrust{verifier: base, trust: trust}, nil
}

// fetchEnvironment names env as package fetch does; newVerifier has refused every other value before.
func fetchEnvironment(env Environment) fetch.Environment {
	switch env {
	case EnvironmentProduction:
		return fetch.Production
	case EnvironmentReference:
		return fetch.Reference
	case EnvironmentTest:
		return fetch.Test
	default:
		return ""
	}
}

// Close ends the refreshing. The copy in memory stands until it is too old.
func (t *FetchingTrust) Close() {
	t.trust.Close()
}

// Check implements [CertificateTrust]. It never fetches.
func (t *FetchingTrust) Check(ctx context.Context, which IDPCertificate, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("%s: no certificate", which)
	}
	store, err := t.trust.Current()
	if err != nil {
		return fmt.Errorf("%s: %w", which, err)
	}
	return t.check(ctx, store, which, certs)
}
