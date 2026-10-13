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

package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

func TestMemBusPubSub(t *testing.T) {
	bus := kv.NewMemBus()
	ctx := t.Context()
	ch, err := bus.Subscribe(ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := bus.Publish(ctx, "c", "hello"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if got != "hello" {
			t.Errorf("got %q, want hello", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no message received")
	}
}

// TestBusRevokerPropagation models two replicas sharing one bus: a revoke on one must reach the other so
// logout/lockout is fleet-wide.
func TestBusRevokerPropagation(t *testing.T) {
	bus := kv.NewMemBus()
	store := kv.NewMemory() // shared durable store, as two replicas share one Postgres
	a := newBusRevoker(bus, store, time.Hour)
	b := newBusRevoker(bus, store, time.Hour)

	a.Revoke("sid-1")
	if !a.IsRevoked("sid-1") {
		t.Fatal("revoke not applied on the originating replica")
	}
	// The other replica sees it asynchronously via the bus.
	deadline := time.Now().Add(2 * time.Second)
	for !b.IsRevoked("sid-1") {
		if time.Now().After(deadline) {
			t.Fatal("revocation did not propagate to the other replica")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if b.IsRevoked("other") {
		t.Error("unrelated sid reported revoked")
	}
}

func TestBusRevokerStartupLoad(t *testing.T) {
	// A revocation already in the durable set is loaded when a fresh replica starts.
	store := kv.NewMemory()
	if err := store.Set(context.Background(), revokedPrefix+"sid-old", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	r := newBusRevoker(kv.NewMemBus(), store, time.Hour)
	if !r.IsRevoked("sid-old") {
		t.Error("startup did not load the durable revoked-set")
	}
}

func TestBusRevokerBackstopWrite(t *testing.T) {
	store := kv.NewMemory()
	r := newBusRevoker(kv.NewMemBus(), store, time.Hour)
	r.Revoke("sid-x")
	if _, found, _ := store.Get(context.Background(), revokedPrefix+"sid-x"); !found {
		t.Error("Revoke did not persist to the durable backstop")
	}
}

func TestBusRevokerReconcileCatchesMissed(t *testing.T) {
	// Simulate a dropped NOTIFY: the revocation lands in the durable set but not via the bus. Reconcile applies it.
	store := kv.NewMemory()
	r := newBusRevoker(kv.NewMemBus(), store, time.Hour)
	if err := store.Set(context.Background(), revokedPrefix+"sid-missed", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if r.IsRevoked("sid-missed") {
		t.Fatal("should not be revoked before reconcile")
	}
	r.reconcile()
	if !r.IsRevoked("sid-missed") {
		t.Error("reconcile did not pick up the durable entry (missed NOTIFY)")
	}
}
