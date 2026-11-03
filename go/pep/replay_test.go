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

package pep_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/pep"
)

func replicaWithReplayCache(t *testing.T, cache dpop.ReplayCache) http.Handler {
	t.Helper()
	jwkSet, err := pep.ParseJWKSet([]byte(publicJWSKSet))
	if err != nil {
		t.Fatal(err)
	}
	builder := pep.NewBuilder().Resource("https://example.com").WithJWKSet(jwkSet)
	if cache != nil {
		builder = builder.WithDPoPReplayCache(cache)
	}
	p, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return p.GuardedHandlerFunc(&pep.EnforcerAuthorizationDPoP{}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func replayRequest(t *testing.T) *http.Request {
	t.Helper()
	return createRequestWithAccessTokenAndDPoP(t, "https://example.com/dpop", []byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour))
}

func statusOf(h http.Handler, req *http.Request) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// RFC 9449 Section 11.1: with a cache the replicas share, a proof replayed at another replica is refused.
func TestRFC9449_11_1_ProofReplayedAtAnotherReplicaIsRefusedWithASharedCache(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(100, nil)
	a, b := replicaWithReplayCache(t, cache), replicaWithReplayCache(t, cache)
	req := replayRequest(t)
	if status := statusOf(a, req); status != http.StatusOK {
		t.Fatalf("first use: status %d", status)
	}
	if status := statusOf(b, req); status != http.StatusUnauthorized {
		t.Fatalf("replay at the other replica: status %d", status)
	}
}

// What the option is for: without it, each replica remembers only its own proofs.
func TestRFC9449_11_1_WithoutASharedCacheEachReplicaKnowsOnlyItsOwnProofs(t *testing.T) {
	a, b := replicaWithReplayCache(t, nil), replicaWithReplayCache(t, nil)
	req := replayRequest(t)
	if status := statusOf(a, req); status != http.StatusOK {
		t.Fatalf("first use: status %d", status)
	}
	if status := statusOf(a, req); status != http.StatusUnauthorized {
		t.Fatalf("replay at the same replica: status %d", status)
	}
	if status := statusOf(b, req); status != http.StatusOK {
		t.Fatalf("at the other replica: status %d", status)
	}
}

type failingReplayCache struct{}

func (failingReplayCache) Seen(string, time.Time) (bool, error) {
	return false, errors.New("store down")
}

func TestRFC9449_11_1_AnErrorFromTheCacheRefusesTheProof(t *testing.T) {
	h := replicaWithReplayCache(t, failingReplayCache{})
	if status := statusOf(h, replayRequest(t)); status != http.StatusInternalServerError {
		t.Fatalf("status %d", status)
	}
}
