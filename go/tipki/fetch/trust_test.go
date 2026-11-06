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

package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
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

// captured is when spec/tsl-detached/testdata was fetched.
var captured = time.Date(2026, 11, 1, 16, 47, 42, 0, time.UTC)

const (
	refList  = "../../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref"
	refRoots = "../../../rust/ti-pki/src/roots-nonprod.json"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type answering tipki.RevocationStatus

func (a answering) Check(context.Context, *x509.Certificate, *x509.Certificate, *tipki.TrustStore) (*tipki.RevocationResult, error) {
	return &tipki.RevocationResult{Status: tipki.RevocationStatus(a), RevokedAt: captured.Add(-time.Hour)}, nil
}

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
			"/roots.json": readFile(t, refRoots),
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

func (p *publisher) trust(t *testing.T) *Trust {
	t.Helper()
	anchor, signerAnchors, err := anchorsFor(Reference)
	if err != nil {
		t.Fatal(err)
	}
	return newTrust(urls{roots: p.URL + "/roots.json", hash: p.URL + "/list.sha2", list: p.URL + "/list"},
		anchor, signerAnchors, answering(tipki.RevocationGood), p.Client(), func() time.Time { return captured }, nextFetch)
}

func (p *publisher) started(t *testing.T) *Trust {
	t.Helper()
	trust := p.trust(t)
	if err := trust.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	return trust
}

// ticking is a clock that starts at from and runs with the real one.
func ticking(from time.Time) func() time.Time {
	start := time.Now()
	return func() time.Time { return from.Add(time.Since(start)) }
}

func TestIDPV007TheFetchedMaterialIsTheVerifiedList(t *testing.T) {
	trust := newPublisher(t).started(t)
	store, err := trust.Current()
	if err != nil {
		t.Fatal(err)
	}
	if store.TSL.TSL.SequenceNumber == 0 || len(store.Roots) == 0 || len(store.Intermediates) == 0 {
		t.Errorf("sequence %d, %d roots, %d CAs", store.TSL.TSL.SequenceNumber, len(store.Roots), len(store.Intermediates))
	}
	if !bytes.Equal(store.Roots[0].Raw, tipki.AnchorNonProd) {
		t.Error("the walk does not start at the environment's anchor")
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
	for _, env := range []Environment{"", "production", "REF"} {
		if _, err := New(env, http.DefaultClient); err == nil {
			t.Errorf("started in the environment %q", env)
		}
	}
	if _, err := New(Reference, nil); err == nil {
		t.Error("started without an HTTP client")
	}
}

func TestIDPV007OnlyANamedEnvironmentIsTaken(t *testing.T) {
	for _, name := range []string{"prod", "ref", "test", "dev"} {
		if env, err := ParseEnvironment(name); err != nil || string(env) != name {
			t.Errorf("%q: %q, %v", name, env, err)
		}
	}
	for _, name := range []string{"", "production", "reference", "REF", " ref"} {
		if _, err := ParseEnvironment(name); err == nil {
			t.Errorf("%q taken", name)
		}
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
	for env, marker := range map[Environment]string{Production: "download.", Reference: "-ref", Test: "-test", Development: "-ref"} {
		urls, err := urlsFor(env)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(urls.roots, "https://") || !strings.HasPrefix(urls.hash, "https://") {
			t.Errorf("%s: roots and hash must be HTTPS: %+v", env, urls)
		}
		if !strings.Contains(urls.hash, marker) || !strings.HasSuffix(urls.hash, ".sha2") {
			t.Errorf("%s: %s", env, urls.hash)
		}
	}
	ref, _ := urlsFor(Reference)
	if dev, _ := urlsFor(Development); dev != ref {
		t.Errorf("dev fetches %+v, not the reference environment's material", dev)
	}
}

func TestIDPV006OnlyProductionTakesTheProductionAnchors(t *testing.T) {
	for _, env := range []Environment{Production, Reference, Test, Development} {
		anchor, signerAnchors, err := anchorsFor(env)
		if err != nil {
			t.Fatal(err)
		}
		wantAnchor, wantSigner := tipki.AnchorNonProd, tipki.TSLSignerAnchorNonProd
		if env == Production {
			wantAnchor, wantSigner = tipki.AnchorProd, tipki.TSLSignerAnchorProd
		}
		if !bytes.Equal(anchor, wantAnchor) || len(signerAnchors) != 1 || !bytes.Equal(signerAnchors[0], wantSigner) {
			t.Errorf("%s: the wrong anchors", env)
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

func TestIDPV008ReadingTheCopyNeverFetches(t *testing.T) {
	pub := newPublisher(t)
	trust := pub.started(t)
	before := pub.requests["/list.sha2"].Load()
	trust.now = func() time.Time { return captured.Add(fetchEvery * 3) }
	if _, err := trust.Current(); err != nil {
		t.Fatal(err)
	}
	if trust.Source().Store() == nil {
		t.Fatal("no snapshot")
	}
	if after := pub.requests["/list.sha2"].Load(); after != before {
		t.Errorf("a read made %d requests", after-before)
	}
}

func TestIDPV008AFailedRefreshKeepsTheCopyUntilItIsTooOld(t *testing.T) {
	pub := newPublisher(t)
	trust := pub.started(t)
	pub.remove("/list.sha2")
	if err := trust.refresh(t.Context()); err == nil {
		t.Fatal("a refresh without a hash")
	}
	trust.now = func() time.Time { return captured.Add(tipki.MaxBundleAge - time.Minute) }
	if _, err := trust.Current(); err != nil {
		t.Errorf("within the limit: %v", err)
	}
	trust.now = func() time.Time { return captured.Add(tipki.MaxBundleAge) }
	_, err := trust.Current()
	if err == nil || !strings.Contains(err.Error(), "the limit is") || !strings.Contains(err.Error(), "answered 404") {
		t.Errorf("at the limit: %v", err)
	}
}

func TestIDPV008AListPastItsNextUpdateIsRefusedHoweverNewTheCopy(t *testing.T) {
	trust := newPublisher(t).started(t)
	past := trust.store.TSL.TSL.NextUpdate.Add(time.Minute)
	trust.fetchedAt = past
	trust.now = func() time.Time { return past }
	_, err := trust.Current()
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
	if trust.store != before || trust.Source().Store() != before {
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

func TestIDPV008CloseWithoutRefreshingReturns(t *testing.T) {
	trust := newPublisher(t).started(t)
	trust.Close()
	trust.Close()
}

func TestTLSV033TheSnapshotIsTheVerifiedCopy(t *testing.T) {
	trust := newPublisher(t).trust(t)
	if trust.Source().Store() != nil {
		t.Fatal("a snapshot before any material")
	}
	if err := trust.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := trust.Current()
	if err != nil {
		t.Fatal(err)
	}
	if trust.Source().Store() != store {
		t.Error("the snapshot is not the verified copy")
	}
}

func TestTLSV033TheSnapshotIsWithdrawnTheMomentTheCopyIsTooOld(t *testing.T) {
	pub := newPublisher(t)
	trust := pub.started(t)
	held := trust.Source().Store()
	if held == nil {
		t.Fatal("no snapshot")
	}
	end, _ := trust.expiry()
	if want := captured.Add(tipki.MaxBundleAge); !end.Equal(want) {
		t.Fatalf("expires at %s, not at %s", end, want)
	}
	// Nothing would fetch for an hour: only the loop's wake at the expiry can withdraw the snapshot.
	trust.now = ticking(end.Add(-50 * time.Millisecond))
	trust.interval = func(bool) time.Duration { return time.Hour }
	before := pub.requests["/list.sha2"].Load()
	trust.start()
	t.Cleanup(trust.Close)
	deadline := time.After(10 * time.Second)
	for trust.Source().Store() != nil {
		select {
		case <-deadline:
			t.Fatal("the snapshot outlived the copy")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if _, err := trust.Current(); err == nil || !strings.Contains(err.Error(), "the limit is") {
		t.Errorf("err = %v", err)
	}
	if after := pub.requests["/list.sha2"].Load(); after != before {
		t.Errorf("withdrawn by %d fetches, not by the expiry", after-before)
	}
	if err := trust.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if trust.Source().Store() == nil {
		t.Error("a good refresh did not restore the snapshot")
	}
}

func TestTLSV050AnUnchangedRefreshKeepsTheSnapshot(t *testing.T) {
	trust := newPublisher(t).started(t)
	held := trust.Source().Store()
	trust.now = func() time.Time { return captured.Add(fetchEvery) }
	if err := trust.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if trust.Source().Store() != held {
		t.Error("the same material was swapped in again")
	}
	if trust.fetchedAt != captured.Add(fetchEvery) {
		t.Errorf("the refresh did not count: fetched at %s", trust.fetchedAt)
	}
}
