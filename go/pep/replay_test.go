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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/pep"
)

func replicaWithReplays(t *testing.T, replays dpop.Replays) http.Handler {
	t.Helper()
	jwkSet, err := pep.ParseJWKSet([]byte(publicJWSKSet))
	if err != nil {
		t.Fatal(err)
	}
	p, err := pep.NewBuilder().Resource("https://example.com").WithJWKSet(jwkSet).WithDPoPReplays(replays).Build()
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

// RFC 9449 Section 11.1: with replays the replicas share, a proof replayed at another replica is refused.
func TestRFC9449_11_1_ProofReplayedAtAnotherReplicaIsRefusedWithSharedReplays(t *testing.T) {
	replays := dpop.NewMemoryReplays(100, nil)
	a, b := replicaWithReplays(t, replays), replicaWithReplays(t, replays)
	req := replayRequest(t)
	if status := statusOf(a, req); status != http.StatusOK {
		t.Fatalf("first use: status %d", status)
	}
	if status := statusOf(b, req); status != http.StatusUnauthorized {
		t.Fatalf("replay at the other replica: status %d", status)
	}
}

// What sharing is for: with replays of its own, each replica remembers only its own proofs.
func TestRFC9449_11_1_WithoutSharedReplaysEachReplicaKnowsOnlyItsOwnProofs(t *testing.T) {
	a, b := replicaWithReplays(t, dpop.NewMemoryReplays(100, nil)), replicaWithReplays(t, dpop.NewMemoryReplays(100, nil))
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

type failingReplays struct{}

func (failingReplays) Seen(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("store down")
}

func TestRFC9449_11_1_AnErrorFromTheReplaysRefusesTheProof(t *testing.T) {
	h := replicaWithReplays(t, failingReplays{})
	if status := statusOf(h, replayRequest(t)); status != http.StatusInternalServerError {
		t.Fatalf("status %d", status)
	}
}

// The PEP picks no backend for the replays: in memory is the host's decision, made knowing its replicas.
func TestServerRule17_BuildRefusesABuilderWithoutReplays(t *testing.T) {
	jwkSet, err := pep.ParseJWKSet([]byte(publicJWSKSet))
	if err != nil {
		t.Fatal(err)
	}
	_, err = pep.NewBuilder().Resource("https://example.com").WithJWKSet(jwkSet).Build()
	if err == nil || !strings.Contains(err.Error(), "WithDPoPReplays") {
		t.Fatalf("got %v", err)
	}
}
