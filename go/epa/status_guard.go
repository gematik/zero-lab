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
	"sync"
	"time"
)

const (
	// statusResultLifetime lets open portal pages share one round of checks.
	statusResultLifetime = 5 * time.Second
	// statusFailureBackoff is longer than the page's refresh, because checking a provider
	// without a session opens one: a provider that is down would otherwise see a new login
	// attempt on every refresh, around the clock.
	statusFailureBackoff = 60 * time.Second
)

// statusGuard stands between the status endpoint and the providers: callers share a round of
// checks for statusResultLifetime, and a provider that failed reports its last error for
// statusFailureBackoff without being contacted.
type statusGuard struct {
	providers []ProviderNumber
	check     func(ProviderNumber) ProviderVAUStatus

	mu     sync.Mutex
	round  *statusRound
	failed map[ProviderNumber]failedStatus
}

// statusRound is one round of checks. providers is set before done closes; expires is guarded
// by statusGuard.mu and stays zero while the round is going.
type statusRound struct {
	done      chan struct{}
	providers []ProviderVAUStatus
	expires   time.Time
}

type failedStatus struct {
	status  ProviderVAUStatus
	retryAt time.Time
}

func newStatusGuard(providers []ProviderNumber, check func(ProviderNumber) ProviderVAUStatus) *statusGuard {
	return &statusGuard{providers: providers, check: check, failed: make(map[ProviderNumber]failedStatus)}
}

// Status returns the current round's result, in the order of the guard's providers, which
// callers must not change. A caller that leaves stops waiting; the round goes on for those
// sharing it, bounded by the session's own timeouts.
func (g *statusGuard) Status(ctx context.Context) ([]ProviderVAUStatus, error) {
	g.mu.Lock()
	round := g.round
	if round == nil || (!round.expires.IsZero() && !time.Now().Before(round.expires)) {
		round = &statusRound{done: make(chan struct{})}
		g.round = round
		go g.runRound(round)
	}
	g.mu.Unlock()

	select {
	case <-round.done:
		return round.providers, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (g *statusGuard) runRound(round *statusRound) {
	results := make([]ProviderVAUStatus, len(g.providers))
	var wg sync.WaitGroup
	for i, provider := range g.providers {
		if status, waiting := g.waitingStatus(provider); waiting {
			results[i] = status
			continue
		}
		wg.Go(func() { results[i] = g.checkProvider(provider) })
	}
	wg.Wait()

	round.providers = results
	g.mu.Lock()
	round.expires = time.Now().Add(statusResultLifetime)
	g.mu.Unlock()
	close(round.done)
}

// waitingStatus returns the provider's last failure while it must not be contacted.
func (g *statusGuard) waitingStatus(provider ProviderNumber) (ProviderVAUStatus, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	failed, ok := g.failed[provider]
	if !ok || !time.Now().Before(failed.retryAt) {
		return ProviderVAUStatus{}, false
	}
	return failed.status, true
}

func (g *statusGuard) checkProvider(provider ProviderNumber) ProviderVAUStatus {
	status := g.check(provider)
	g.mu.Lock()
	defer g.mu.Unlock()
	if status.Error != "" {
		g.failed[provider] = failedStatus{status: status, retryAt: time.Now().Add(statusFailureBackoff)}
	} else {
		delete(g.failed, provider)
	}
	return status
}
