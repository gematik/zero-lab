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
	"crypto/sha256"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
	"github.com/gematik/zero-lab/go/tipki/fetch"
)

// The download and refresh are proven in go/tipki/fetch; these prove idpd's checks over the store it yields.

// fetched is a FetchingTrust over the store the fetch path loads from the captured reference publication:
// the same roots.json, list, signature and signer status, verified the same way.
func fetched(t *testing.T) *FetchingTrust {
	t.Helper()
	base, err := newVerifier(EnvironmentReference, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	base.checker = answering(tipki.RevocationGood)
	base.now = func() time.Time { return captured }
	store, err := base.load(t.Context(), &tipki.Bundle{
		Label:           "fetched",
		AnchorSHA256:    sha256.Sum256(tipki.AnchorNonProd),
		Roots:           readFile(t, "../../rust/ti-pki/src/roots-nonprod.json"),
		TSL:             readFile(t, refList+".xml"),
		TSLSignature:    readFile(t, refList+".sig"),
		TSLSignerStatus: readFile(t, refList+".ocsp"),
		FetchedAt:       captured,
	}, captured, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &FetchingTrust{verifier: base, current: func() (*tipki.TrustStore, error) { return store, nil }}
}

func TestIDPV007TheFetchedMaterialVerifiesTheRealCertificates(t *testing.T) {
	trust := fetched(t)
	for which, name := range map[IDPCertificate]string{DiscoverySigner: "disc.ru.idp.rise.der", TokenSigner: "main.ru.idp.rise.der"} { //nolint:gosec // file names of test certificates, not credentials
		if err := trust.Check(t.Context(), which, idpCertificate(t, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestIDPV007NoEnvironmentNoStart(t *testing.T) {
	if _, err := NewFetchingTrust(EnvironmentUnset, http.DefaultClient); err == nil || !strings.Contains(err.Error(), "no IDP-Dienst environment") {
		t.Errorf("started without an environment: %v", err)
	}
	for env, want := range map[Environment]fetch.Environment{EnvironmentProduction: fetch.Production, EnvironmentReference: fetch.Reference, EnvironmentTest: fetch.Test} {
		if got := fetchEnvironment(env); got != want {
			t.Errorf("%d fetches %q", env, got)
		}
	}
}

func TestIDPV008ALoginIsRefusedWhenTheCopyNoLongerStands(t *testing.T) {
	trust := fetched(t)
	trust.current = func() (*tipki.TrustStore, error) { return nil, errors.New("trust material is 24h0m0s old") }
	err := trust.Check(t.Context(), DiscoverySigner, idpCertificate(t, "disc.ru.idp.rise.der"))
	if err == nil || !strings.Contains(err.Error(), "24h0m0s old") {
		t.Errorf("err = %v", err)
	}
	if err := fetched(t).Check(t.Context(), DiscoverySigner, nil); err == nil {
		t.Error("no certificate")
	}
}

func TestIDPV007ExactlyOneSourceIsConfigured(t *testing.T) {
	config := ClientConfig{Environment: EnvironmentReference, TrustFetch: true, TrustBundlePath: "x"}
	if _, err := trustFromConfig(config, http.DefaultClient); err == nil || !strings.Contains(err.Error(), "exclude") {
		t.Errorf("both: %v", err)
	}
	if _, err := trustFromConfig(ClientConfig{Environment: EnvironmentReference}, http.DefaultClient); err == nil {
		t.Error("neither")
	}
}

// The live reference environment, with nothing mounted. Gated: `just idpd-trust-fetch-test`.
func TestIDPV007TheLiveReferenceEnvironment(t *testing.T) {
	if os.Getenv("IDPD_TRUST_FETCH") == "" {
		t.Skip("IDPD_TRUST_FETCH not set: needs a route to gematik's hosts; proves the download and both IDP certificates live")
	}
	trust, err := NewFetchingTrust(EnvironmentReference, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(trust.Close)
	recorded := &checked{trust: trust}
	client, err := NewClientFromConfig(ClientConfig{
		Environment: EnvironmentReference, ClientID: "trust-test", RedirectURI: "https://rp/cb",
		Scopes: []string{"openid"}, Trust: recorded,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetchSigningKey(t.Context(), client.Metadata.SigningKeyURI, client.httpClient, recorded); err != nil {
		t.Fatal(err)
	}
	store, err := trust.current()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TSL sequence %d", store.TSL.TSL.SequenceNumber)
	for i, which := range recorded.passed {
		t.Logf("%s: %q valid for an IDP-Dienst (idpd-sig, OCSP)", which, recorded.subjects[i])
	}
	if err := trust.Check(context.Background(), TokenSigner, nil); err == nil {
		t.Error("no certificate")
	}
}
