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

package kv_test

import (
	"sync"
	"testing"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/kvtest"
)

func TestMemory_Contract(t *testing.T) {
	kvtest.Store(t, func(*testing.T) kv.Store { return kv.NewMemory() })
}

func TestMemory_MarkerContract(t *testing.T) {
	kvtest.Marker(t, func(_ *testing.T, mark func(string, []byte) string) kv.Store {
		return kv.NewMemory(kv.WithMemoryMark(mark))
	})
}

func TestMemory_FeedContract(t *testing.T) {
	kvtest.Feed(t, func(*testing.T) kv.Store { return kv.NewMemory() })
}

func TestMemory_TxContract(t *testing.T) {
	kvtest.Tx(t, func(*testing.T) kv.Store { return kv.NewMemory() })
}

func TestMemory_SealedFeedContract(t *testing.T) {
	kvtest.SealedFeed(t, func(*testing.T) kv.Store { return kv.NewMemory() })
}

func TestMemory_ResealerContract(t *testing.T) {
	kvtest.Resealer(t, func(_ *testing.T, mark func(string, []byte) string) kv.Store {
		return kv.NewMemory(kv.WithMemoryMark(mark))
	})
}

// memory is everything a store of this package is.
type memory interface {
	kv.Store
	kv.Swapper
	kv.Marker
	kv.Transactor
	kv.Feed
	kv.NumberedFeed
	kv.Classed
}

// shared is the one memory store of a test as each of its pods has it: a pod that closes its store closes
// its own connections, not the database.
type shared struct{ memory }

func (shared) Close() error { return nil }

// memoryPods is a database in memory for the suites that run several pods: one store per class, which
// keeps the marks of sealed records for every pod, also for one that asks for none.
func memoryPods() kvtest.Open {
	var mu sync.Mutex
	stores := map[bool]kv.Store{}
	return func(pod kvtest.Pod) (kv.Store, error) {
		mu.Lock()
		defer mu.Unlock()
		if stores[pod.Ephemeral] == nil {
			opts := []kv.MemoryOption{kv.WithMemoryMark(kv.SealedMarker(nil))}
			if pod.Ephemeral {
				opts = append(opts, kv.WithMemoryEphemeral())
			}
			stores[pod.Ephemeral] = kv.NewMemory(opts...)
		}
		return shared{stores[pod.Ephemeral].(memory)}, nil
	}
}

func TestMemory_PodsRule5SealedRecordsOpenOnlyWhereAndAsWhatTheyWereSealed(t *testing.T) {
	kvtest.Sealing(t, memoryPods())
}

func TestMemory_PodsRule5UnsealedRecordsOfBeforeAreNotTakenForSealedOnes(t *testing.T) {
	kvtest.Unsealed(t, memoryPods())
}

func TestMemory_PodsRule22TheKeysChangeWhilePodsHoldDifferentFiles(t *testing.T) {
	kvtest.Rotation(t, memoryPods())
}

func TestMemory_PodsRule22SealedEventsAcrossAChangeOfKeys(t *testing.T) {
	kvtest.SealedEvents(t, memoryPods())
}

func TestMemory_PodsRule11ARevocationReachesTheFollowersOfOtherPods(t *testing.T) {
	kvtest.Revocations(t, memoryPods())
}

func TestMemory_PodsRule11LoginsOfOneUserThroughSeveralPods(t *testing.T) {
	kvtest.Logins(t, memoryPods())
}

// The contract of kv.Transactor: what a transaction read with Get stays as read until its end, against a
// writer outside a transaction as against another transaction, for a record that is there and one that is
// not.
func TestMemory_WhatATransactionReadIsHeldAgainstWritersOutsideIt(t *testing.T) {
	kvtest.TxOutside(t, func(*testing.T) kv.Store { return kv.NewMemory() })
}
