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
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
)

// publisher serves the captured reference list as gematik's hosts do, and can be told to misbehave.
type publisher struct {
	*httptest.Server
	mu       sync.Mutex
	files    map[string][]byte
	requests map[string]*atomic.Int64
}

func newPublisher(t *testing.T) *publisher {
	t.Helper()
	list := readFile(t, refList+".xml")
	digest := sha256.Sum256(list)
	pub := &publisher{
		files: map[string][]byte{
			"/roots.json": readFile(t, "../../rust/ti-pki/src/roots-nonprod.json"),
			"/list.sha2":  []byte(strings.ToUpper(hex.EncodeToString(digest[:])) + "  ECC-RSA_TSL-ref.xml\n"),
			"/list.xml":   list,
			"/list.sig":   readFile(t, refList+".sig"),
			"/list.ocsp":  readFile(t, refList+".ocsp"),
		},
		requests: make(map[string]*atomic.Int64),
	}
	for path := range pub.files {
		pub.requests[path] = new(atomic.Int64)
	}
	pub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if counter, ok := pub.requests[r.URL.Path]; ok {
			counter.Add(1)
		}
		pub.mu.Lock()
		body, ok := pub.files[r.URL.Path]
		pub.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(pub.Close)
	return pub
}

func (p *publisher) set(path string, body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.files[path] = body
}

func (p *publisher) remove(path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.files, path)
}

func (p *publisher) trust(t *testing.T) *FetchingTrust {
	t.Helper()
	base, err := newVerifier(EnvironmentReference, p.Client())
	if err != nil {
		t.Fatal(err)
	}
	base.checker = answering(tipki.RevocationGood)
	base.now = func() time.Time { return captured }
	return newFetchingTrust(base, trustURLs{roots: p.URL + "/roots.json", hash: p.URL + "/list.sha2", list: p.URL + "/list"}, p.Client())
}

func (p *publisher) started(t *testing.T) *FetchingTrust {
	t.Helper()
	trust := p.trust(t)
	if err := trust.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	return trust
}

func TestIDPV007TheFetchedMaterialVerifiesTheRealCertificates(t *testing.T) {
	trust := newPublisher(t).started(t)
	for which, name := range map[IDPCertificate]string{DiscoverySigner: "disc.ru.idp.rise.der", TokenSigner: "main.ru.idp.rise.der"} { //nolint:gosec // file names of test certificates, not credentials
		if err := trust.Check(t.Context(), which, idpCertificate(t, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestIDPV007AListTheHTTPSHashDoesNotNameIsRefused(t *testing.T) {
	pub := newPublisher(t)
	other := sha256.Sum256([]byte("a newer list"))
	pub.set("/list.sha2", []byte(hex.EncodeToString(other[:])+"\n"))
	err := pub.trust(t).refresh(t.Context())
	if err == nil || !strings.Contains(err.Error(), "hashes to") {
		t.Errorf("err = %v", err)
	}
}

func TestIDPV007AHashDoesNotExcuseABadSignature(t *testing.T) {
	pub := newPublisher(t)
	list := append(readFile(t, refList+".xml"), '\n')
	digest := sha256.Sum256(list)
	pub.set("/list.xml", list)
	pub.set("/list.sha2", []byte(hex.EncodeToString(digest[:])))
	if err := pub.trust(t).refresh(t.Context()); err == nil {
		t.Error("a list the signature does not cover")
	}
}

func TestIDPV007NoTrustMaterialNoStart(t *testing.T) {
	for _, path := range []string{"/roots.json", "/list.sha2", "/list.xml", "/list.sig"} {
		pub := newPublisher(t)
		pub.remove(path)
		if err := pub.trust(t).refresh(t.Context()); err == nil {
			t.Errorf("started without %s", path)
		}
	}
	for _, body := range []string{"", "not a hash", strings.Repeat("a", 63)} {
		pub := newPublisher(t)
		pub.set("/list.sha2", []byte(body))
		if err := pub.trust(t).refresh(t.Context()); err == nil {
			t.Errorf("started with the hash %q", body)
		}
	}
	if _, err := NewFetchingTrust(EnvironmentUnset, http.DefaultClient); err == nil {
		t.Error("started without an environment")
	}
}

func TestIDPV007ARedirectIsNotFollowed(t *testing.T) {
	pub := newPublisher(t)
	redirecting := httptest.NewServer(http.RedirectHandler(pub.URL+"/roots.json", http.StatusFound))
	t.Cleanup(redirecting.Close)
	trust := pub.trust(t)
	trust.urls.roots = redirecting.URL
	if err := trust.refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("err = %v", err)
	}
}

func TestIDPV007TheHostsAreFixedPerEnvironment(t *testing.T) {
	for env, marker := range map[Environment]string{EnvironmentProduction: "download.", EnvironmentReference: "-ref", EnvironmentTest: "-test"} {
		urls, err := urlsFor(env)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(urls.roots, "https://") || !strings.HasPrefix(urls.hash, "https://") {
			t.Errorf("env %d: roots and hash must be HTTPS: %+v", env, urls)
		}
		if !strings.Contains(urls.hash, marker) || !strings.HasSuffix(urls.hash, ".sha2") {
			t.Errorf("env %d: %s", env, urls.hash)
		}
	}
}

func TestIDPV007WithoutOCSPFileTheSignerIsAskedOnline(t *testing.T) {
	pub := newPublisher(t)
	pub.remove("/list.ocsp")
	revoked := pub.trust(t)
	revoked.checker = answering(tipki.RevocationRevoked)
	if err := revoked.refresh(t.Context()); err == nil {
		t.Error("a revoked signer")
	}
	if err := pub.trust(t).refresh(t.Context()); err != nil {
		t.Errorf("a good signer: %v", err)
	}
}

func TestIDPV008ALoginNeverFetches(t *testing.T) {
	pub := newPublisher(t)
	trust := pub.started(t)
	before := pub.requests["/list.sha2"].Load()
	trust.now = func() time.Time { return captured.Add(fetchEvery * 3) }
	if err := trust.Check(t.Context(), DiscoverySigner, idpCertificate(t, "disc.ru.idp.rise.der")); err != nil {
		t.Fatal(err)
	}
	if after := pub.requests["/list.sha2"].Load(); after != before {
		t.Errorf("a check made %d requests", after-before)
	}
}

func TestIDPV008AFailedRefreshKeepsTheCopyUntilItIsTooOld(t *testing.T) {
	pub := newPublisher(t)
	trust := pub.started(t)
	certs := idpCertificate(t, "disc.ru.idp.rise.der")
	pub.remove("/list.sha2")
	if err := trust.refresh(t.Context()); err == nil {
		t.Fatal("a refresh without a hash")
	}
	trust.now = func() time.Time { return captured.Add(tipki.MaxBundleAge - time.Minute) }
	if err := trust.Check(t.Context(), DiscoverySigner, certs); err != nil {
		t.Errorf("within the limit: %v", err)
	}
	trust.now = func() time.Time { return captured.Add(tipki.MaxBundleAge) }
	err := trust.Check(t.Context(), DiscoverySigner, certs)
	if err == nil || !strings.Contains(err.Error(), "the limit is") {
		t.Errorf("at the limit: %v", err)
	}
}

func TestIDPV008AListPastItsNextUpdateIsRefusedHoweverNewTheCopy(t *testing.T) {
	trust := newPublisher(t).started(t)
	past := trust.store.TSL.TSL.NextUpdate.Add(time.Minute)
	trust.fetchedAt = past
	trust.now = func() time.Time { return past }
	err := trust.Check(t.Context(), DiscoverySigner, idpCertificate(t, "disc.ru.idp.rise.der"))
	if err == nil || !strings.Contains(err.Error(), "NextUpdate") {
		t.Errorf("err = %v", err)
	}
}

func TestIDPV008AnOlderListIsRefusedAndTheCopyStays(t *testing.T) {
	pub := newPublisher(t)
	trust := pub.started(t)
	newer := trust.store.TSL.State()
	newer.SequenceNumber++
	trust.state = &newer
	before := trust.store
	trust.listHash = ""
	if err := trust.refresh(t.Context()); err == nil {
		t.Error("an older list")
	}
	if trust.store != before {
		t.Error("the copy was replaced")
	}
}

func TestIDPV008AnUnchangedListIsNotDownloadedAgain(t *testing.T) {
	pub := newPublisher(t)
	trust := pub.started(t)
	if err := trust.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := pub.requests["/list.xml"].Load(); got != 1 {
		t.Errorf("the list was downloaded %d times", got)
	}
	if got := pub.requests["/list.ocsp"].Load(); got != 2 {
		t.Errorf("the signer's status was fetched %d times", got)
	}
}

func TestIDPV008TheRefreshRunsInTheBackground(t *testing.T) {
	pub := newPublisher(t)
	trust := pub.started(t)
	trust.interval = func(bool) time.Duration { return time.Millisecond }
	before := pub.requests["/list.sha2"].Load()
	trust.start()
	deadline := time.After(10 * time.Second)
	for pub.requests["/list.sha2"].Load() <= before {
		select {
		case <-deadline:
			t.Fatal("no refresh in the background")
		case <-time.After(time.Millisecond):
		}
	}
	trust.Close()
}

func TestIDPV008TheNextFetchIsSoonerAfterAFailure(t *testing.T) {
	if got := nextFetch(true); got != fetchRetry {
		t.Errorf("after a failure: %s", got)
	}
	for range 100 {
		if got := nextFetch(false); got > fetchEvery || got <= fetchEvery-10*time.Minute {
			t.Fatalf("after a success: %s", got)
		}
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
	if _, err := fetchSigningKey(client.Metadata.SigningKeyURI, client.httpClient, recorded); err != nil {
		t.Fatal(err)
	}
	t.Logf("TSL sequence %d", trust.store.TSL.TSL.SequenceNumber)
	for i, which := range recorded.passed {
		t.Logf("%s: %q valid for an IDP-Dienst (idpd-sig, OCSP)", which, recorded.subjects[i])
	}
	if err := trust.Check(context.Background(), TokenSigner, nil); err == nil {
		t.Error("no certificate")
	}
}
