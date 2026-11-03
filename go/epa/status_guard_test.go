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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// countingCheck answers from healthy and counts the checks per provider.
type countingCheck struct {
	mu      sync.Mutex
	healthy map[ProviderNumber]bool
	calls   map[ProviderNumber]int
	took    time.Duration
}

func newCountingCheck(failing ...ProviderNumber) *countingCheck {
	c := &countingCheck{
		healthy: map[ProviderNumber]bool{ProviderNumber1: true, ProviderNumber2: true},
		calls:   map[ProviderNumber]int{},
	}
	for _, provider := range failing {
		c.healthy[provider] = false
	}
	return c
}

func (c *countingCheck) check(provider ProviderNumber) ProviderVAUStatus {
	time.Sleep(c.took)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls[provider]++
	if !c.healthy[provider] {
		return ProviderVAUStatus{Number: provider, Error: "provider is down"}
	}
	return ProviderVAUStatus{Number: provider}
}

func (c *countingCheck) setHealthy(provider ProviderNumber, healthy bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.healthy[provider] = healthy
}

func (c *countingCheck) count(provider ProviderNumber) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[provider]
}

var guardedProviders = []ProviderNumber{ProviderNumber1, ProviderNumber2}

func TestStatusCallersWithinFiveSecondsShareOneResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := newCountingCheck()
		check.took = time.Second
		guard := newStatusGuard(guardedProviders, check.check)

		var wg sync.WaitGroup
		for range 10 {
			wg.Go(func() {
				if _, err := guard.Status(t.Context()); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()

		time.Sleep(5*time.Second - time.Nanosecond)
		if _, err := guard.Status(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := check.count(ProviderNumber1); got != 1 {
			t.Errorf("%d checks of provider 1 within the 5 seconds, want 1", got)
		}
	})
}

func TestStatusChecksAHealthyProviderAgainOnceTheResultExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := newCountingCheck()
		guard := newStatusGuard(guardedProviders, check.check)

		if _, err := guard.Status(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Second)
		if _, err := guard.Status(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := check.count(ProviderNumber1); got != 2 {
			t.Errorf("%d checks of provider 1, want 2", got)
		}
	})
}

func TestStatusDoesNotTryAFailedProviderAgainForSixtySeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := newCountingCheck(ProviderNumber2)
		guard := newStatusGuard(guardedProviders, check.check)

		for range 11 {
			providers, err := guard.Status(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if got := providers[1]; got.Number != ProviderNumber2 || got.Error != "provider is down" {
				t.Fatalf("the failed provider's last error must be reported meanwhile: %+v", got)
			}
			time.Sleep(5 * time.Second)
		}
		if got := check.count(ProviderNumber2); got != 1 {
			t.Errorf("%d checks of the failed provider within 55 seconds, want 1", got)
		}
		if got := check.count(ProviderNumber1); got != 11 {
			t.Errorf("%d checks of the healthy provider, want 11: it must not wait for the failed one", got)
		}
	})
}

func TestStatusTriesAFailedProviderAgainAfterSixtySecondsAndReportsItsRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := newCountingCheck(ProviderNumber2)
		guard := newStatusGuard(guardedProviders, check.check)

		if _, err := guard.Status(t.Context()); err != nil {
			t.Fatal(err)
		}
		check.setHealthy(ProviderNumber2, true)
		time.Sleep(60 * time.Second)

		providers, err := guard.Status(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if providers[1].Error != "" {
			t.Errorf("recovered provider still reports %q", providers[1].Error)
		}

		time.Sleep(5 * time.Second)
		if _, err := guard.Status(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := check.count(ProviderNumber2); got != 3 {
			t.Errorf("%d checks, want 3: a recovered provider is checked like a healthy one", got)
		}
	})
}

func TestStatusCheckOutlivesTheCallerThatStartedIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := newCountingCheck()
		check.took = 3 * time.Second
		guard := newStatusGuard(guardedProviders, check.check)

		leaving, leave := context.WithCancel(t.Context())
		first := make(chan error, 1)
		go func() {
			_, err := guard.Status(leaving)
			first <- err
		}()
		synctest.Wait()
		leave()
		if err := <-first; !errors.Is(err, context.Canceled) {
			t.Fatalf("leaving caller: %v", err)
		}

		if _, err := guard.Status(t.Context()); err != nil {
			t.Fatalf("second caller shares the check and must get its result: %v", err)
		}
		if got := check.count(ProviderNumber1); got != 1 {
			t.Errorf("%d checks, want 1", got)
		}
	})
}

func TestProxyStatusAnswersThroughTheGuard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := newCountingCheck(ProviderNumber2)
		proxy := &Proxy{
			config:      &ProxyConfig{Name: "d1", SecurityFunctions: &SecurityFunctions{}},
			Env:         EnvDev,
			statusGuard: newStatusGuard(guardedProviders, check.check),
		}

		var status ProxyStatus
		for range 2 {
			rec := httptest.NewRecorder()
			proxy.HandleProxyStatus(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("a failed provider must not be an HTTP error: %d", rec.Code)
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
				t.Fatal(err)
			}
		}
		if status.Name != "d1" || len(status.Providers) != 2 || status.Providers[1].Error == "" {
			t.Errorf("status %+v", status)
		}
		if got := check.count(ProviderNumber1); got != 1 {
			t.Errorf("%d checks for two requests, want 1", got)
		}
	})
}
