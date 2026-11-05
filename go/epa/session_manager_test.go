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

package epa

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/epa/vau"
)

func TestASlowLoginDoesNotHoldAnotherProvider(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	ready := &Session{}
	sm := &sessionManager{
		sessions: map[ProviderNumber]*Session{ProviderNumber2: ready},
		login: func(ProviderNumber) (*Session, error) {
			close(started)
			<-release
			return nil, errors.New("timed out")
		},
	}
	go func() { _, _ = sm.GetSession(ProviderNumber1) }()
	<-started
	defer close(release)

	done := make(chan *Session)
	go func() {
		session, _ := sm.GetSession(ProviderNumber2)
		done <- session
	}()
	select {
	case got := <-done:
		if got != ready {
			t.Error("another session was returned")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an open session waited for another provider's login")
	}
}

func TestConcurrentCallersOpenOneSessionPerProvider(t *testing.T) {
	var logins atomic.Int32
	sm := &sessionManager{
		sessions: map[ProviderNumber]*Session{},
		login: func(ProviderNumber) (*Session, error) {
			logins.Add(1)
			time.Sleep(20 * time.Millisecond)
			return &Session{}, nil
		},
	}
	var wg sync.WaitGroup
	sessions := make([]*Session, 8)
	for i := range sessions {
		wg.Go(func() {
			session, err := sm.GetSession(ProviderNumber1)
			if err != nil {
				t.Error(err)
			}
			sessions[i] = session
		})
	}
	wg.Wait()
	if logins.Load() != 1 {
		t.Errorf("%d logins", logins.Load())
	}
	for _, session := range sessions {
		if session != sessions[0] {
			t.Fatal("callers got different sessions")
		}
	}
}

func TestServerRule2_OnlyAKnownProviderIsReached(t *testing.T) {
	// A nil session manager: reaching it would panic, so a refusal comes before any login.
	p := &Proxy{}
	for _, number := range []string{"99", "0", "-1", "4", "x"} {
		for name, handle := range map[string]http.HandlerFunc{
			"outside the VAU": p.HandleForwardToProvider,
			"into the VAU":    p.HandleForwardToVAUProvider,
		} {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.SetPathValue("providerNumber", number)
			req.SetPathValue("path", "x")
			rec := httptest.NewRecorder()
			handle(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s, provider %s: %d", name, number, rec.Code)
			}
		}
	}
}

// A_24628-01: the PU/nonPU byte is 1 only for a ciphertext made in the production environment.
func TestA_24628_OnlyAProductionChannelCarriesTheProductionByte(t *testing.T) {
	for env, want := range map[Env]vau.Env{EnvProd: vau.EnvPU, EnvRef: vau.EnvNonPU, EnvTest: vau.EnvNonPU, EnvDev: vau.EnvNonPU} {
		if got := vauEnv(env); got != want {
			t.Errorf("%s: %d, want %d", env, got, want)
		}
	}
}

// Server rule 2, no SSRF: whatever path a request names, the host stays the provider's.
func TestServerRule2_TheRequestPicksOnlyThePathAtTheProvider(t *testing.T) {
	const base = "https://epa-as-1.dev.epa4all.de"
	for _, path := range []string{"x", "a/b", "../../x", "//evil.example/x", "@evil.example", "%2F%2Fevil.example", "http://evil.example/"} {
		got, err := providerURL(base, path)
		if err != nil {
			continue
		}
		u, err := url.Parse(got)
		if err != nil || u.Host != "epa-as-1.dev.epa4all.de" || u.Scheme != "https" {
			t.Errorf("%q became %s", path, got)
		}
	}
}
