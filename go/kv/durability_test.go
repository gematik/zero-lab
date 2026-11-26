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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/kvtest"
)

func TestDurabilityOf_AStoreSaysItsClassAndAWrapperPassesItOn(t *testing.T) {
	durable, ephemeral := kv.NewMemory(), kv.NewMemory(kv.WithMemoryEphemeral())
	if got := kv.DurabilityOf(durable); got != kv.Durable {
		t.Errorf("a memory store: %v", got)
	}
	if got := kv.DurabilityOf(ephemeral); got != kv.Ephemeral {
		t.Errorf("an ephemeral memory store: %v", got)
	}
	ring := testRing(t, testRingLine("k1", 1))
	if got := kv.DurabilityOf(kv.NewSealed(ephemeral, ring, "test")); got != kv.Ephemeral {
		t.Errorf("a sealed store over an ephemeral one: %v", got)
	}
	if got := kv.DurabilityOf(kv.NewSealed(durable, ring, "test")); got != kv.Durable {
		t.Errorf("a sealed store over a durable one: %v", got)
	}
	if got := kv.DurabilityOf(storeOnly{ephemeral}); got != kv.Durable {
		t.Errorf("a store that does not say its class: %v", got)
	}
}

func TestMemory_EphemeralContract(t *testing.T) {
	kvtest.Store(t, func(*testing.T) kv.Store { return kv.NewMemory(kv.WithMemoryEphemeral()) })
	kvtest.Ephemeral(t, func(*testing.T) kv.Store { return kv.NewMemory(kv.WithMemoryEphemeral()) })
}

// A record is sealed for the class of the store it is written to. One that was sealed for a durable store
// does not open when it is found in an ephemeral one, nor the other way: whoever can write to the cache
// cannot put a session there, and a cached document cannot be made a durable record.
func TestSealed_ARecordOfOneClassDoesNotOpenInTheOther(t *testing.T) {
	ctx := context.Background()
	ring := testRing(t, testRingLine("k1", 1))
	durableRaw, ephemeralRaw := kv.NewMemory(), kv.NewMemory(kv.WithMemoryEphemeral())
	durable, ephemeral := kv.NewSealed(durableRaw, ring, "test"), kv.NewSealed(ephemeralRaw, ring, "test")
	if err := durable.Set(ctx, "k", []byte("a session"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := ephemeral.Set(ctx, "k", []byte("a document"), time.Minute); err != nil {
		t.Fatal(err)
	}
	fromDurable, _, _ := durableRaw.Get(ctx, "k")
	fromEphemeral, _, _ := ephemeralRaw.Get(ctx, "k")
	if err := ephemeralRaw.Set(ctx, "moved", fromDurable, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := durableRaw.Set(ctx, "moved", fromEphemeral, time.Minute); err != nil {
		t.Fatal(err)
	}
	// Under the same key too: only the class differs.
	if err := ephemeralRaw.Set(ctx, "k", fromDurable, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := durableRaw.Set(ctx, "k", fromEphemeral, time.Minute); err != nil {
		t.Fatal(err)
	}
	for name, read := range map[string]func() error{
		"a durable record in the ephemeral store":                     func() error { _, _, err := ephemeral.Get(ctx, "k"); return err },
		"an ephemeral record in the durable store":                    func() error { _, _, err := durable.Get(ctx, "k"); return err },
		"a durable record in the ephemeral store, under another key":  func() error { _, _, err := ephemeral.Get(ctx, "moved"); return err },
		"an ephemeral record in the durable store, under another key": func() error { _, _, err := durable.Take(ctx, "moved"); return err },
	} {
		if err := read(); !errors.Is(err, kv.ErrIntegrity) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
